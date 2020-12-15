"""Classes to manage credential revocation."""

import json
import logging
from typing import Mapping, Sequence, Text

from ..core.error import BaseError
from ..core.profile import Profile
from ..indy.issuer import IndyIssuer
from ..storage.error import StorageNotFoundError

from .indy import IndyRevocation
from .models.issuer_rev_reg_record import IssuerRevRegRecord
from .models.issuer_cred_rev_record import IssuerCredRevRecord


class RevocationManagerError(BaseError):
    """Revocation manager error."""


class RevocationManager:
    """Class for managing revocation operations."""

    def __init__(self, profile: Profile):
        """
        Initialize a RevocationManager.

        Args:
            context: The context for this revocation manager
        """
        self._profile = profile
        self._logger = logging.getLogger(__name__)

    async def revoke_credential_by_cred_ex_id(
        self, cred_ex_id: str, publish: bool = False
    ):
        """
        Revoke a credential by its credential exchange identifier at issue.

        Optionally, publish the corresponding revocation registry delta to the ledger.

        Args:
            cred_ex_id: credential exchange identifier
            publish: whether to publish the resulting revocation registry delta,
                along with any revocations pending against it

        """
        try:
            async with self._profile.session() as session:
                rec = await IssuerCredRevRecord.retrieve_by_cred_ex_id(
                    session,
                    cred_ex_id,
                )
        except StorageNotFoundError as err:
            raise RevocationManagerError(
                "No issuer credential revocation record found for "
                f"credential exchange id {cred_ex_id}"
            ) from err
        return await self.revoke_credential(
            rev_reg_id=rec.rev_reg_id, cred_rev_id=rec.cred_rev_id, publish=publish
        )

    async def revoke_credential(
        self,
        rev_reg_id: str,
        cred_rev_id: str,
        publish: bool = False,
    ):
        """
        Revoke a credential.

        Optionally, publish the corresponding revocation registry delta to the ledger.

        Args:
            rev_reg_id: revocation registry id
            cred_rev_id: credential revocation id
            publish: whether to publish the resulting revocation registry delta,
                along with any revocations pending against it

        """
        issuer = self._profile.inject(IndyIssuer)

        revoc = IndyRevocation(self._profile)
        issuer_rr_rec = await revoc.get_issuer_rev_reg_record(rev_reg_id)
        if not issuer_rr_rec:
            raise RevocationManagerError(
                f"No revocation registry record found for id {rev_reg_id}"
            )

        if publish:
            rev_reg = await revoc.get_ledger_registry(rev_reg_id)
            await rev_reg.get_or_fetch_local_tails_path()

            # pick up pending revocations on input revocation registry
            crids = list(set(issuer_rr_rec.pending_pub + [cred_rev_id]))
            (delta_json, _) = await issuer.revoke_credentials(
                issuer_rr_rec.revoc_reg_id, issuer_rr_rec.tails_local_path, crids
            )
            if delta_json:
                issuer_rr_rec.revoc_reg_entry = json.loads(delta_json)
                await issuer_rr_rec.send_entry(self._profile)
                async with self._profile.session() as session:
                    await issuer_rr_rec.clear_pending(session)

        else:
            async with self._profile.session() as session:
                await issuer_rr_rec.mark_pending(session, cred_rev_id)

    async def publish_pending_revocations(
        self, rrid2crid: Mapping[Text, Sequence[Text]] = None
    ) -> Mapping[Text, Sequence[Text]]:
        """
        Publish pending revocations to the ledger.

        Args:
            rrid2crid: Mapping from revocation registry identifiers to all credential
                revocation identifiers within each to publish. Specify null/empty map
                for all revocation registries. Specify empty sequence per revocation
                registry identifier for all pending within the revocation registry;
                e.g.,

                {} - publish all pending revocations from all revocation registries

                {
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:0": [],
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:1": ["1", "2"]

                } - publish:
                    - all pending revocations from all revocation registry tagged 0
                    - pending ["1", "2"] from revocation registry tagged 1
                    - no pending revocations from any other revocation registries.

        Returns: mapping from each revocation registry id to its cred rev ids published.
        """
        result = {}
        issuer = self._profile.inject(IndyIssuer)

        txn = await self._profile.transaction()
        issuer_rr_recs = await IssuerRevRegRecord.query_by_pending(txn)
        for issuer_rr_rec in issuer_rr_recs:
            rrid = issuer_rr_rec.revoc_reg_id
            crids = []
            if not rrid2crid:
                crids = issuer_rr_rec.pending_pub
            elif rrid in rrid2crid:
                crids = [
                    crid
                    for crid in issuer_rr_rec.pending_pub
                    if crid in (rrid2crid[rrid] or []) or not rrid2crid[rrid]
                ]
            if crids:
                # FIXME - must use the same transaction
                (delta_json, failed_crids) = await issuer.revoke_credentials(
                    issuer_rr_rec.revoc_reg_id,
                    issuer_rr_rec.tails_local_path,
                    crids,
                )
                issuer_rr_rec.revoc_reg_entry = json.loads(delta_json)
                await issuer_rr_rec.send_entry(self._profile)
                published = [crid for crid in crids if crid not in failed_crids]
                result[issuer_rr_rec.revoc_reg_id] = published
                await issuer_rr_rec.clear_pending(txn, published)
                await txn.commit()

        return result

    async def clear_pending_revocations(
        self, purge: Mapping[Text, Sequence[Text]] = None
    ) -> Mapping[Text, Sequence[Text]]:
        """
        Clear pending revocation publications.

        Args:
            purge: Mapping from revocation registry identifiers to all credential
                revocation identifiers within each to clear. Specify null/empty map
                for all revocation registries. Specify empty sequence per revocation
                registry identifier for all pending within the revocation registry;
                e.g.,

                {} - clear all pending revocations from all revocation registries

                {
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:0": [],
                    "R17v42T4pk...:4:R17v42T4pk...:3:CL:19:tag:CL_ACCUM:1": ["1", "2"]

                } - clear
                    - all pending revocations from all revocation registry tagged 0
                    - pending ["1", "2"] from revocation registry tagged 1
                    - no pending revocations from any other revocation registries.

        Returns:
            mapping from revocation registry id to its remaining
            cred rev ids still marked pending, omitting revocation registries
            with no remaining pending publications.

        """
        result = {}

        async with self._profile.transaction() as txn:
            issuer_rr_recs = await IssuerRevRegRecord.query_by_pending(txn)
            for issuer_rr_rec in issuer_rr_recs:
                rrid = issuer_rr_rec.revoc_reg_id
                await issuer_rr_rec.clear_pending(txn, (purge or {}).get(rrid))
                if issuer_rr_rec.pending_pub:
                    result[rrid] = issuer_rr_rec.pending_pub
            await txn.commit()

        return result
