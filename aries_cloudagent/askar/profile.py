"""Manage Aries-Askar profile interaction."""

import asyncio
import logging
import time

# import traceback

from typing import Any, Mapping
from weakref import ref

from aries_askar import generate_raw_key, Session, Store, StoreError

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
from ..storage.base import BaseStorage, BaseStorageSearch
from ..wallet.base import BaseWallet
from ..wallet.crypto import validate_seed

from .store import AskarStoreConfig, AskarOpenStore

LOGGER = logging.getLogger(__name__)


class AskarProfile(Profile):
    """Provide access to Aries-Askar profile interaction methods."""

    BACKEND_NAME = "askar"

    def __init__(self, opened: AskarOpenStore, context: InjectionContext = None):
        """Create a new AskarProfile instance."""
        super().__init__(context=context, name=opened.name, created=opened.created)
        self.opened = opened
        self.ledger_pool: IndyVdrLedgerPool = None
        self.init_ledger_pool()
        self.bind_providers()

    @property
    def name(self) -> str:
        """Accessor for the profile name."""
        return self.opened.name

    @property
    def store(self) -> Store:
        """Accessor for the opened Store instance."""
        return self.opened.store

    def init_ledger_pool(self):
        """Initialize the ledger pool."""
        if self.settings.get("ledger.disabled"):
            LOGGER.info("Ledger support is disabled")
            return

        pool_name = self.settings.get("ledger.pool_name", "default")
        keepalive = int(self.settings.get("ledger.keepalive", 5))
        read_only = bool(self.settings.get("ledger.read_only", False))
        if read_only:
            LOGGER.error("Note: setting ledger to read-only mode")
        genesis_transactions = self.settings.get("ledger.genesis_transactions")
        cache = self.context.injector.inject(BaseCache, required=False)
        self.ledger_pool = IndyVdrLedgerPool(
            pool_name,
            keepalive=keepalive,
            cache=cache,
            genesis_transactions=genesis_transactions,
            read_only=read_only,
        )

    def bind_providers(self):
        """Initialize the profile-level instance providers."""
        injector = self._context.injector

        injector.bind_provider(
            BaseStorageSearch,
            ClassProvider(
                "aries_cloudagent.storage.askar.AskarStorageSearch", ref(self)
            ),
        )

        injector.bind_provider(
            IndyHolder,
            ClassProvider(
                "aries_cloudagent.indy.credx.holder.IndyCredxHolder",
                ref(self),
            ),
        )
        injector.bind_provider(
            IndyIssuer,
            ClassProvider(
                "aries_cloudagent.indy.credx.issuer.IndyCredxIssuer", ref(self)
            ),
        )

        if self.ledger_pool:
            injector.bind_provider(
                BaseLedger, ClassProvider(IndyVdrLedger, self.ledger_pool, ref(self))
            )
            injector.bind_provider(
                IndyVerifier,
                ClassProvider(
                    "aries_cloudagent.indy.credx.verifier.IndyCredxVerifier",
                    ref(self),
                ),
            )

    def session(self, context: InjectionContext = None) -> ProfileSession:
        """Start a new interactive session with no transaction support requested."""
        return AskarProfileSession(self, False, context=context)

    def transaction(self, context: InjectionContext = None) -> ProfileSession:
        """
        Start a new interactive session with commit and rollback support.

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
        context: InjectionContext = None,
        settings: Mapping[str, Any] = None
    ):
        """Create a new IndySdkProfileSession instance."""
        super().__init__(profile=profile, context=context, settings=settings)
        if is_txn:
            self._opener = self.profile.store.transaction()
        else:
            self._opener = self.profile.store.session()
        self._handle: Session = None
        self._acquire_start: float = None
        self._acquire_end: float = None

    @property
    def handle(self) -> Session:
        """Accessor for the Session instance."""
        return self._handle

    @property
    def store(self) -> Store:
        """Accessor for the Store instance."""
        return self._handle and self._handle.store

    @property
    def is_transaction(self) -> bool:
        """Check if the session supports commit and rollback operations."""
        if self._handle:
            return self._handle.is_transaction
        return self._opener.is_transaction

    async def _setup(self):
        """Create the session or transaction connection, if needed."""
        self._acquire_start = time.perf_counter()
        try:
            self._handle = await asyncio.wait_for(self._opener, 10)
        except StoreError as err:
            raise ProfileError("Error opening store session") from err
        self._acquire_end = time.perf_counter()
        self._opener = None

        injector = self._context.injector
        injector.bind_provider(
            BaseWallet,
            ClassProvider("aries_cloudagent.wallet.askar.AskarWallet", ref(self)),
        )
        injector.bind_provider(
            BaseStorage,
            ClassProvider("aries_cloudagent.storage.askar.AskarStorage", ref(self)),
        )

    async def _teardown(self, commit: bool = None):
        """Dispose of the session or transaction connection."""
        if commit:
            try:
                await self._handle.commit()
            except StoreError as err:
                raise ProfileError("Error committing transaction") from err
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
        if self._handle:
            self._check_duration()


class AskarProfileManager(ProfileManager):
    """Manager for Aries-Askar stores."""

    async def provision(self, config: Mapping[str, Any] = None) -> Profile:
        """Provision a new instance of a profile."""
        store_config = AskarStoreConfig(config)
        opened = await store_config.open_store(provision=True)
        return AskarProfile(opened, self.context)

    async def open(self, config: Mapping[str, Any] = None) -> Profile:
        """Open an instance of an existing profile."""
        store_config = AskarStoreConfig(config)
        opened = await store_config.open_store(provision=False)
        return AskarProfile(opened, self.context)

    @classmethod
    async def generate_store_key(self, seed: str = None) -> str:
        """Generate a raw store key."""
        return await generate_raw_key(validate_seed(seed))
