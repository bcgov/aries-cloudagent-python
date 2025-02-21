"""Manage Aries-Askar profile interaction."""

import asyncio
import logging
import time
from typing import Any, Mapping, Optional
from weakref import ref

from aries_askar import AskarError, Session, Store

from ..cache.base import BaseCache
from ..config.injection_context import InjectionContext
from ..config.provider import ClassProvider
from ..core.error import ProfileError
from ..core.profile import Profile, ProfileManager, ProfileSession
from ..indy.holder import IndyHolder
from ..indy.issuer import IndyIssuer
from ..indy.verifier import IndyVerifier
from ..ledger.base import BaseLedger
from ..ledger.indy_vdr import IndyVdrLedger, IndyVdrLedgerPool
from ..resolver.did_resolver import DIDResolver
from ..storage.base import BaseStorage, BaseStorageSearch
from ..storage.vc_holder.base import VCHolder
from ..utils.multi_ledger import get_write_ledger_config_for_profile
from ..wallet.base import BaseWallet
from ..wallet.crypto import validate_seed
from .store import AskarOpenStore, AskarStoreConfig

LOGGER = logging.getLogger(__name__)


class AskarProfile(Profile):
    """Provide access to Aries-Askar profile interaction methods."""

    BACKEND_NAME = "askar"

    def __init__(
        self,
        opened: AskarOpenStore,
        context: Optional[InjectionContext] = None,
        *,
        profile_id: Optional[str] = None,
    ):
        """Private constructor. Use 'create' to instantiate."""
        super().__init__(
            context=context, name=profile_id or opened.name, created=opened.created
        )
        self.opened = opened
        self.ledger_pool: Optional[IndyVdrLedgerPool] = None
        self.profile_id = profile_id

    @classmethod
    async def create(
        cls,
        opened: AskarOpenStore,
        context: Optional[InjectionContext] = None,
        *,
        profile_id: Optional[str] = None,
    ) -> "AskarProfile":
        """Asynchronously create a new AskarProfile instance."""
        profile = cls(opened, context, profile_id=profile_id)
        await profile.init_ledger_pool()
        await profile.bind_providers()
        return profile

    @property
    def name(self) -> str:
        """Accessor for the profile name."""
        return self.profile_id or self.opened.name

    @property
    def store(self) -> Store:
        """Accessor for the opened Store instance."""
        return self.opened.store

    async def remove(self):
        """Remove the profile."""
        if self.profile_id:
            await self.store.remove_profile(self.profile_id)

    async def init_ledger_pool(self):
        """Initialize the ledger pool."""
        if self.settings.get("ledger.disabled"):
            LOGGER.info("Ledger support is disabled")
            return
        if self.settings.get("ledger.genesis_transactions"):
            pool_name = self.settings.get("ledger.pool_name", "default")
            keepalive = int(self.settings.get("ledger.keepalive", 5))
            read_only = bool(self.settings.get("ledger.read_only", False))
            socks_proxy = self.settings.get("ledger.socks_proxy")
            if read_only:
                LOGGER.warning("Note: setting ledger to read-only mode")
            genesis_transactions = self.settings.get("ledger.genesis_transactions")
            cache = self.context.injector.inject_or(BaseCache)
            self.ledger_pool = await IndyVdrLedgerPool.get_or_create(
                name=pool_name,
                keepalive=keepalive,
                cache=cache,
                genesis_transactions=genesis_transactions,
                read_only=read_only,
                socks_proxy=socks_proxy,
            )

    async def bind_providers(self):
        """Initialize the profile-level instance providers."""
        injector = self._context.injector

        if self.context.settings.get("experiment.didcomm_v2"):
            from didcomm_messaging.resolver import DIDResolver as DMPResolver

            injector.bind_provider(
                DMPResolver,
                ClassProvider(
                    "acapy_agent.didcomm_v2.adapters.ResolverAdapter",
                    ref(self),
                    ClassProvider.Inject(DIDResolver),
                ),
            )

        injector.bind_provider(
            BaseStorageSearch,
            ClassProvider("acapy_agent.storage.askar.AskarStorageSearch", ref(self)),
        )

        injector.bind_provider(
            IndyHolder,
            ClassProvider(
                "acapy_agent.indy.credx.holder.IndyCredxHolder",
                ref(self),
            ),
        )
        injector.bind_provider(
            IndyIssuer,
            ClassProvider("acapy_agent.indy.credx.issuer.IndyCredxIssuer", ref(self)),
        )
        injector.soft_bind_provider(
            VCHolder,
            ClassProvider(
                "acapy_agent.storage.vc_holder.askar.AskarVCHolder",
                ClassProvider.Inject(Profile),
            ),
        )
        if (
            self.settings.get("ledger.ledger_config_list")
            and len(self.settings.get("ledger.ledger_config_list")) >= 1
        ):
            write_ledger_config = get_write_ledger_config_for_profile(
                settings=self.settings
            )
            cache = self.context.injector.inject_or(BaseCache)
            ledger_pool = await IndyVdrLedgerPool.get_or_create(
                name=write_ledger_config.get("pool_name")
                or write_ledger_config.get("id"),
                keepalive=write_ledger_config.get("keepalive"),
                cache=cache,
                genesis_transactions=write_ledger_config.get("genesis_transactions"),
                read_only=write_ledger_config.get("read_only"),
                socks_proxy=write_ledger_config.get("socks_proxy"),
            )
            injector.bind_provider(
                BaseLedger, ClassProvider(IndyVdrLedger, ledger_pool, ref(self))
            )
            self.settings["ledger.write_ledger"] = write_ledger_config.get("id")
            if (
                "endorser_alias" in write_ledger_config
                and "endorser_did" in write_ledger_config
            ):
                self.settings["endorser.endorser_alias"] = write_ledger_config.get(
                    "endorser_alias"
                )
                self.settings["endorser.endorser_public_did"] = write_ledger_config.get(
                    "endorser_did"
                )
        elif self.ledger_pool:
            injector.bind_provider(
                BaseLedger, ClassProvider(IndyVdrLedger, self.ledger_pool, ref(self))
            )
        if self.ledger_pool or self.settings.get("ledger.ledger_config_list"):
            injector.bind_provider(
                IndyVerifier,
                ClassProvider(
                    "acapy_agent.indy.credx.verifier.IndyCredxVerifier",
                    ref(self),
                ),
            )

    def session(self, context: Optional[InjectionContext] = None) -> ProfileSession:
        """Start a new interactive session with no transaction support requested."""
        return AskarProfileSession(self, False, context=context)

    def transaction(self, context: Optional[InjectionContext] = None) -> ProfileSession:
        """Start a new interactive session with commit and rollback support.

        If the current backend does not support transactions, then commit
        and rollback operations of the session will not have any effect.
        """
        return AskarProfileSession(self, True, context=context)

    async def close(self):
        """Close the profile instance."""
        if self.opened:
            await self.opened.close()
            self.opened = None


class AskarProfileSession(ProfileSession):
    """An active connection to the profile management backend."""

    def __init__(
        self,
        profile: AskarProfile,
        is_txn: bool,
        *,
        context: Optional[InjectionContext] = None,
        settings: Mapping[str, Any] = None,
    ):
        """Create a new IndySdkProfileSession instance."""
        super().__init__(profile=profile, context=context, settings=settings)
        if is_txn:
            self._opener = self.profile.store.transaction(profile.profile_id)
        else:
            self._opener = self.profile.store.session(profile.profile_id)
        self._profile = profile
        self._handle: Optional[Session] = None
        self._acquire_start: Optional[float] = None
        self._acquire_end: Optional[float] = None

    @property
    def handle(self) -> Session:
        """Accessor for the Session instance."""
        return self._handle

    @property
    def store(self) -> Store:
        """Accessor for the Store instance."""
        return self._profile and self._profile.store

    @property
    def is_transaction(self) -> bool:
        """Check if the session supports commit and rollback operations."""
        if self._handle:  # opened
            return self._handle.is_transaction
        if self._opener:  # opening
            return self._opener.is_transaction

        raise ProfileError("Session not open")

    async def _setup(self):
        """Create the session or transaction connection, if needed."""
        self._acquire_start = time.perf_counter()
        try:
            self._handle = await asyncio.wait_for(self._opener, 10)
        except AskarError as err:
            raise ProfileError("Error opening store session") from err
        self._acquire_end = time.perf_counter()
        self._opener = None

        injector = self._context.injector
        injector.bind_provider(
            BaseWallet,
            ClassProvider("acapy_agent.wallet.askar.AskarWallet", ref(self)),
        )
        injector.bind_provider(
            BaseStorage,
            ClassProvider("acapy_agent.storage.askar.AskarStorage", ref(self)),
        )

        if self.profile.settings.get("experiment.didcomm_v2"):
            from didcomm_messaging import (
                CryptoService,
                DIDCommMessaging,
                PackagingService,
                RoutingService,
                SecretsManager,
            )
            from didcomm_messaging.resolver import DIDResolver as DMPResolver

            injector.bind_provider(
                SecretsManager,
                ClassProvider(
                    "acapy_agent.didcomm_v2.adapters.SecretsAdapter", ref(self)
                ),
            )

            injector.bind_provider(
                DIDCommMessaging,
                ClassProvider(
                    DIDCommMessaging,
                    ClassProvider.Inject(CryptoService),
                    ClassProvider.Inject(SecretsManager),
                    ClassProvider.Inject(DMPResolver),
                    ClassProvider.Inject(PackagingService),
                    ClassProvider.Inject(RoutingService),
                ),
            )

    async def _teardown(self, commit: Optional[bool] = None):
        """Dispose of the session or transaction connection."""
        if commit:
            try:
                await self._handle.commit()
            except AskarError as err:
                raise ProfileError("Error committing transaction") from err
        if self._handle:
            await self._handle.close()
        self._handle = None
        self._check_duration()

    def _check_duration(self):
        # LOGGER.error(
        #     "release session after %.2f, acquire took %.2f",
        #     end - self._acquire_end,
        #     self._acquire_end - self._acquire_start,
        # )
        # end = time.perf_counter()
        # if end - self._acquire_end > 1.0:
        #     LOGGER.error("Long session")
        #     traceback.print_stack(limit=5)
        pass

    def __del__(self):
        """Delete magic method."""
        if hasattr(self, "_handle") and self._handle:
            self._check_duration()


class AskarProfileManager(ProfileManager):
    """Manager for Aries-Askar stores."""

    async def provision(
        self, context: InjectionContext, config: Mapping[str, Any] = None
    ) -> Profile:
        """Provision a new instance of a profile."""
        store_config = AskarStoreConfig(config)
        opened = await store_config.open_store(
            provision=True, in_memory=config.get("test")
        )
        return await AskarProfile.create(opened, context)

    async def open(
        self, context: InjectionContext, config: Mapping[str, Any] = None
    ) -> Profile:
        """Open an instance of an existing profile."""
        store_config = AskarStoreConfig(config)
        opened = await store_config.open_store(
            provision=False, in_memory=config.get("test")
        )
        return await AskarProfile.create(opened, context)

    @classmethod
    async def generate_store_key(self, seed: Optional[str] = None) -> str:
        """Generate a raw store key."""
        return Store.generate_raw_key(validate_seed(seed))
