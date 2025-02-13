"""Indy revocation registry management."""

import logging
from typing import Optional, Sequence, Tuple

from uuid_utils import uuid4

from ..core.profile import Profile
from ..ledger.base import BaseLedger
from ..ledger.multiple_ledger.ledger_requests_executor import (
    GET_CRED_DEF,
    GET_REVOC_REG_DEF,
    IndyLedgerRequestsExecutor,
)
from ..multitenant.base import BaseMultitenantManager
from ..protocols.endorse_transaction.v1_0.util import (
    get_endorser_connection_id,
    is_author_role,
)
from ..storage.base import StorageNotFoundError
from ..wallet.askar import CATEGORY_DID
from ..wallet.error import WalletNotFoundError
from .error import (
    RevocationError,
    RevocationInvalidStateValueError,
    RevocationNotSupportedError,
    RevocationRegistryBadSizeError,
)
from .models.issuer_rev_reg_record import IssuerRevRegRecord
from .models.revocation_registry import RevocationRegistry
from .util import notify_revocation_reg_init_event

LOGGER = logging.getLogger(__name__)


class IndyRevocation:
    """Class for managing Indy credential revocation."""

    REV_REG_CACHE = {}

    def __init__(self, profile: Profile):
        """Initialize the IndyRevocation instance."""
        self._profile = profile

    async def init_issuer_registry(
        self,
        cred_def_id: str,
        max_cred_num: Optional[int] = None,
        revoc_def_type: Optional[str] = None,
        tag: Optional[str] = None,
        create_pending_rev_reg: bool = False,
        endorser_connection_id: Optional[str] = None,
        notify: bool = True,
    ) -> IssuerRevRegRecord:
        """Create a new revocation registry record for a credential definition."""
        multitenant_mgr = self._profile.inject_or(BaseMultitenantManager)
        if multitenant_mgr:
            ledger_exec_inst = IndyLedgerRequestsExecutor(self._profile)
        else:
            ledger_exec_inst = self._profile.inject(IndyLedgerRequestsExecutor)
        ledger = (
            await ledger_exec_inst.get_ledger_for_identifier(
                cred_def_id,
                txn_record_type=GET_CRED_DEF,
            )
        )[1]
        async with ledger:
            cred_def = await ledger.get_credential_definition(cred_def_id)
        if not cred_def:
            raise RevocationNotSupportedError("Credential definition not found")
        if not cred_def["value"].get("revocation"):
            raise RevocationNotSupportedError(
                "Credential definition does not support revocation"
            )
        if max_cred_num and not (
            RevocationRegistry.MIN_SIZE <= max_cred_num <= RevocationRegistry.MAX_SIZE
        ):
            raise RevocationRegistryBadSizeError(
                f"Bad revocation registry size: {max_cred_num}"
            )

        record_id = str(uuid4())
        issuer_did = cred_def_id.split(":")[0]
        # Try and get a did:indy did from nym value stored as a did
        async with self._profile.session() as session:
            try:
                indy_did = await session.handle.fetch(
                    CATEGORY_DID, f"did:indy:{issuer_did}"
                )
            except WalletNotFoundError:
                indy_did = None

        record = IssuerRevRegRecord(
            new_with_id=True,
            record_id=record_id,
            cred_def_id=cred_def_id,
            issuer_did=indy_did.name if indy_did else issuer_did,
            max_cred_num=max_cred_num,
            revoc_def_type=revoc_def_type,
            tag=tag,
        )
        revoc_def_type = record.revoc_def_type
        rtag = record.tag or record_id
        record.revoc_reg_id = f"{issuer_did}:4:{cred_def_id}:{revoc_def_type}:{rtag}"
        async with self._profile.session() as session:
            await record.save(session, reason="Init revocation registry")

        if endorser_connection_id is None and is_author_role(self._profile):
            endorser_connection_id = await get_endorser_connection_id(self._profile)
            if not endorser_connection_id:
                raise RevocationError(reason="Endorser connection not found")

        if notify:
            await notify_revocation_reg_init_event(
                self._profile,
                record.record_id,
                create_pending_rev_reg=create_pending_rev_reg,
                endorser_connection_id=endorser_connection_id,
            )

        return record

    async def handle_full_registry(self, revoc_reg_id: str):
        """Update the registry status and start the next registry generation."""
        await self._set_registry_status(revoc_reg_id, IssuerRevRegRecord.STATE_FULL)

    async def decommission_registry(self, cred_def_id: str):
        """Decommission post-init registries and start the next registry generation."""
        async with self._profile.session() as session:
            registries = await IssuerRevRegRecord.query_by_cred_def_id(
                session, cred_def_id
            )

        # decommission everything except init
        recs = list(
            filter(lambda r: r.state != IssuerRevRegRecord.STATE_INIT, registries)
        )

        for rec in recs:
            LOGGER.debug(f"decommission {rec.state} rev. reg.")
            LOGGER.debug(f"revoc_reg_id: {rec.revoc_reg_id}")
            LOGGER.debug(f"cred_def_id: {cred_def_id}")
            # decommission active registry, we need to init a replacement
            init = IssuerRevRegRecord.STATE_ACTIVE == rec.state
            await self._set_registry_status(
                rec.revoc_reg_id, IssuerRevRegRecord.STATE_DECOMMISSIONED, init
            )

        return recs

    async def _set_registry_status(
        self, revoc_reg_id: str, state: str, init: bool = True
    ):
        """Update the registry status and start the next registry generation."""
        if state not in IssuerRevRegRecord.STATES:
            raise RevocationInvalidStateValueError(
                reason=f"{state} is not a valid Revocation Registry state value."
            )
        async with self._profile.transaction() as txn:
            registry = await IssuerRevRegRecord.retrieve_by_revoc_reg_id(
                txn, revoc_reg_id, for_update=True
            )
            if registry.state == state:
                return
            await registry.set_state(
                txn,
                state,
            )
            await txn.commit()

        if (state in IssuerRevRegRecord.TERMINAL_STATES) and init:
            return await self.init_issuer_registry(
                registry.cred_def_id,
                registry.max_cred_num,
                registry.revoc_def_type,
            )

        return

    async def get_active_issuer_rev_reg_record(
        self, cred_def_id: str
    ) -> IssuerRevRegRecord:
        """Return current active registry for issuing a given credential definition.

        Args:
            cred_def_id: ID of the base credential definition
        """
        async with self._profile.session() as session:
            current = sorted(
                await IssuerRevRegRecord.query_by_cred_def_id(
                    session, cred_def_id, IssuerRevRegRecord.STATE_ACTIVE
                )
            )
        if current:
            return current[0]  # active record is oldest published but not full
        raise StorageNotFoundError(
            f"No active issuer revocation record found for cred def id {cred_def_id}"
        )

    async def get_issuer_rev_reg_record(self, revoc_reg_id: str) -> IssuerRevRegRecord:
        """Return a revocation registry record by identifier.

        Args:
            revoc_reg_id: ID of the revocation registry
        """
        async with self._profile.session() as session:
            return await IssuerRevRegRecord.retrieve_by_revoc_reg_id(
                session, revoc_reg_id
            )

    async def list_issuer_registries(self) -> Sequence[IssuerRevRegRecord]:
        """List the issuer's current revocation registries."""
        async with self._profile.session() as session:
            return await IssuerRevRegRecord.query(session)

    async def get_issuer_rev_reg_delta(
        self,
        rev_reg_id: str,
        timestamp_from: Optional[int] = None,
        timestamp_to: Optional[int] = None,
    ) -> dict:
        """Check ledger for revocation status for a given revocation registry.

        Args:
            rev_reg_id (str): ID of the revocation registry
            timestamp_from (int, optional): The sequence number to start from (exclusive).
                Defaults to None.
            timestamp_to (int, optional): The sequence number to end at (inclusive).
                Defaults to None.

        Returns:
            dict: The revocation registry delta.

        """
        ledger = await self.get_ledger_for_registry(rev_reg_id)
        async with ledger:
            (rev_reg_delta, _) = await ledger.get_revoc_reg_delta(
                rev_reg_id,
                timestamp_from,
                timestamp_to,
            )

        return rev_reg_delta

    async def get_or_create_active_registry(
        self, cred_def_id: str
    ) -> Optional[Tuple[IssuerRevRegRecord, RevocationRegistry]]:
        """Fetch the active revocation registry.

        If there is no active registry then creation of a new registry will be
        triggered and the caller should retry after a delay.
        """
        try:
            active_rev_reg_rec = await self.get_active_issuer_rev_reg_record(cred_def_id)
            rev_reg = active_rev_reg_rec.get_registry()
            await rev_reg.get_or_fetch_local_tails_path()
            return active_rev_reg_rec, rev_reg
        except StorageNotFoundError:
            pass

        async with self._profile.session() as session:
            full_registries = await IssuerRevRegRecord.query_by_cred_def_id(
                session, cred_def_id, None, IssuerRevRegRecord.STATE_FULL, 1
            )

            # all registries are full, create a new one
            if not full_registries:
                # Use any registry to get max cred num
                any_registry = await IssuerRevRegRecord.query_by_cred_def_id(
                    session, cred_def_id, limit=1
                )
                if not any_registry:
                    raise RevocationError(
                        f"No revocation registry record found in issuer wallet for cred def id {cred_def_id}"  # noqa: E501
                    )
                any_registry = any_registry[0]
                await self.init_issuer_registry(
                    cred_def_id,
                    max_cred_num=any_registry.max_cred_num,
                )
            # if there is a posted registry, activate oldest
            else:
                posted_registries = await IssuerRevRegRecord.query_by_cred_def_id(
                    session, cred_def_id, IssuerRevRegRecord.STATE_POSTED, None, None
                )
                if posted_registries:
                    posted_registries = sorted(
                        posted_registries, key=lambda r: r.created_at
                    )
                    await self._set_registry_status(
                        revoc_reg_id=posted_registries[0].revoc_reg_id,
                        state=IssuerRevRegRecord.STATE_ACTIVE,
                    )
        return None

    async def get_ledger_registry(self, revoc_reg_id: str) -> RevocationRegistry:
        """Get a revocation registry from the ledger, fetching as necessary."""
        if revoc_reg_id in IndyRevocation.REV_REG_CACHE:
            return IndyRevocation.REV_REG_CACHE[revoc_reg_id]

        ledger = await self.get_ledger_for_registry(revoc_reg_id)

        async with ledger:
            rev_reg = RevocationRegistry.from_definition(
                await ledger.get_revoc_reg_def(revoc_reg_id), True
            )
            IndyRevocation.REV_REG_CACHE[revoc_reg_id] = rev_reg
            return rev_reg

    async def get_ledger_for_registry(self, revoc_reg_id: str) -> BaseLedger:
        """Get the ledger for the given registry."""
        multitenant_mgr = self._profile.inject_or(BaseMultitenantManager)
        if multitenant_mgr:
            ledger_exec_inst = IndyLedgerRequestsExecutor(self._profile)
        else:
            ledger_exec_inst = self._profile.inject(IndyLedgerRequestsExecutor)
        ledger = (
            await ledger_exec_inst.get_ledger_for_identifier(
                revoc_reg_id,
                txn_record_type=GET_REVOC_REG_DEF,
            )
        )[1]
        return ledger
