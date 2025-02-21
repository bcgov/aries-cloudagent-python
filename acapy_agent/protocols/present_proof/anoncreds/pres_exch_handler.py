"""Utilities for anoncreds presentation exchange attachment."""

import json
import logging
import time
from typing import Dict, Optional, Protocol, Tuple

from ....anoncreds.holder import AnonCredsHolder, AnonCredsHolderError
from ....anoncreds.models.credential_definition import CredDef
from ....anoncreds.models.revocation import RevRegDef
from ....anoncreds.models.schema import AnonCredsSchema
from ....anoncreds.models.utils import (
    extract_non_revocation_intervals_from_proof_request,
)
from ....anoncreds.registry import AnonCredsRegistry
from ....anoncreds.revocation import AnonCredsRevocation
from ....askar.profile_anon import AskarAnoncredsProfile
from ....core.error import BaseError
from ....core.profile import Profile

LOGGER = logging.getLogger(__name__)


class AnonCredsPresExchHandlerError(BaseError):
    """Base class for Anoncreds Presentation Exchange related errors."""


class AnonCredsProofRequestContainer(Protocol):
    """Protocol for a class that contains an AC Proof Request."""

    def get_ac_proof_request(self) -> dict:
        """Retrieve proof request object."""
        ...


class AnonCredsPresExchHandler:
    """Base Presentation Exchange Handler."""

    def __init__(
        self,
        profile: Profile,
    ):
        """Initialize PresExchange Handler."""
        super().__init__()
        self._profile = profile
        self.holder = AnonCredsHolder(profile)

    def _get_requested_referents(
        self,
        proof_request: dict,
        requested_credentials: dict,
        non_revoc_intervals: dict,
    ) -> dict:
        """Get requested referents for a proof request and requested credentials.

        Returns a dictionary that looks like:
        {
          "referent-0": {"cred_id": "0", "non_revoked": {"from": ..., "to": ...}},
          "referent-1": {"cred_id": "1", "non_revoked": {"from": ..., "to": ...}}
        }
        """

        requested_referents = {}
        attr_creds = requested_credentials.get("requested_attributes", {})
        req_attrs = proof_request.get("requested_attributes", {})
        for reft in attr_creds:
            requested_referents[reft] = {"cred_id": attr_creds[reft]["cred_id"]}
            if reft in req_attrs and reft in non_revoc_intervals:
                requested_referents[reft]["non_revoked"] = non_revoc_intervals[reft]

        pred_creds = requested_credentials.get("requested_predicates", {})
        req_preds = proof_request.get("requested_predicates", {})
        for reft in pred_creds:
            requested_referents[reft] = {"cred_id": pred_creds[reft]["cred_id"]}
            if reft in req_preds and reft in non_revoc_intervals:
                requested_referents[reft]["non_revoked"] = non_revoc_intervals[reft]
        return requested_referents

    async def _get_credentials(self, requested_referents: dict):
        """Extract mapping of presentation referents to credential ids."""
        credentials = {}
        for reft in requested_referents:
            credential_id = requested_referents[reft]["cred_id"]
            if credential_id not in credentials:
                credentials[credential_id] = json.loads(
                    await self.holder.get_credential(credential_id)
                )
        return credentials

    def _remove_superfluous_timestamps(self, requested_credentials, credentials):
        """Remove any timestamps that cannot correspond to non-revoc intervals."""
        for r in ("requested_attributes", "requested_predicates"):
            for reft, req_item in requested_credentials.get(r, {}).items():
                if not credentials[req_item["cred_id"]].get(
                    "rev_reg_id"
                ) and req_item.pop("timestamp", None):
                    LOGGER.info(
                        f"Removed superfluous timestamp from requested_credentials {r} "
                        f"{reft} for non-revocable credential {req_item['cred_id']}"
                    )

    async def _get_ledger_objects(
        self, credentials: dict
    ) -> Tuple[Dict[str, AnonCredsSchema], Dict[str, CredDef], Dict[str, RevRegDef]]:
        """Get all schemas, credential definitions, and revocation registries in use."""
        schemas = {}
        cred_defs = {}
        revocation_registries = {}

        for credential in credentials.values():
            schema_id = credential["schema_id"]
            anoncreds_registry = self._profile.inject(AnonCredsRegistry)
            if schema_id not in schemas:
                schemas[schema_id] = (
                    await anoncreds_registry.get_schema(self._profile, schema_id)
                ).schema
            cred_def_id = credential["cred_def_id"]
            if cred_def_id not in cred_defs:
                cred_defs[cred_def_id] = (
                    await anoncreds_registry.get_credential_definition(
                        self._profile, cred_def_id
                    )
                ).credential_definition
            if credential.get("rev_reg_id"):
                revocation_registry_id = credential["rev_reg_id"]
                if revocation_registry_id not in revocation_registries:
                    rev_reg = (
                        await anoncreds_registry.get_revocation_registry_definition(
                            self._profile, revocation_registry_id
                        )
                    ).revocation_registry
                    revocation_registries[revocation_registry_id] = rev_reg

        return schemas, cred_defs, revocation_registries

    async def _get_revocation_lists(self, requested_referents: dict, credentials: dict):
        """Get revocation lists.

        Get revocation lists with non-revocation interval defined in
        "non_revoked" of the presentation request or attributes
        """
        epoch_now = int(time.time())
        rev_lists = {}
        for precis in requested_referents.values():  # cred_id, non-revoc interval
            credential_id = precis["cred_id"]
            if not credentials[credential_id].get("rev_reg_id"):
                continue
            if "timestamp" in precis:
                continue
            rev_reg_id = credentials[credential_id]["rev_reg_id"]

            anoncreds_registry = self._profile.inject(AnonCredsRegistry)
            reft_non_revoc_interval = precis.get("non_revoked")
            if reft_non_revoc_interval:
                key = (
                    f"{rev_reg_id}_"
                    f"{reft_non_revoc_interval.get('from', 0)}_"
                    f"{reft_non_revoc_interval.get('to', epoch_now)}"
                )
                if key not in rev_lists:
                    result = await anoncreds_registry.get_revocation_list(
                        self._profile,
                        rev_reg_id,
                        reft_non_revoc_interval.get("to", epoch_now),
                    )

                    rev_lists[key] = (
                        rev_reg_id,
                        credential_id,
                        result.revocation_list.serialize(),
                        result.revocation_list.timestamp,
                    )
                for stamp_me in requested_referents.values():
                    # often one cred satisfies many requested attrs/preds
                    if stamp_me["cred_id"] == credential_id:
                        stamp_me["timestamp"] = rev_lists[key][3]

        return rev_lists

    async def _get_revocation_states(
        self, revocation_registries: dict, credentials: dict, rev_lists: dict
    ):
        """Get revocation states to prove non-revoked."""
        revocation_states = {}
        for (
            rev_reg_id,
            credential_id,
            rev_list,
            timestamp,
        ) in rev_lists.values():
            if rev_reg_id not in revocation_states:
                revocation_states[rev_reg_id] = {}
            rev_reg_def = revocation_registries[rev_reg_id]
            revocation = AnonCredsRevocation(self._profile)
            tails_local_path = await revocation.get_or_fetch_local_tails_path(rev_reg_def)
            try:
                revocation_states[rev_reg_id][timestamp] = json.loads(
                    await self.holder.create_revocation_state(
                        credentials[credential_id]["cred_rev_id"],
                        rev_reg_def.serialize(),
                        rev_list,
                        tails_local_path,
                    )
                )
            except AnonCredsHolderError as e:
                LOGGER.error(
                    f"Failed to create revocation state: {e.error_code}, {e.message}"
                )
                raise e
        return revocation_states

    def _set_timestamps(self, requested_credentials: dict, requested_referents: dict):
        for referent, precis in requested_referents.items():
            if "timestamp" not in precis:
                continue
            if referent in requested_credentials["requested_attributes"]:
                requested_credentials["requested_attributes"][referent]["timestamp"] = (
                    precis["timestamp"]
                )
            if referent in requested_credentials["requested_predicates"]:
                requested_credentials["requested_predicates"][referent]["timestamp"] = (
                    precis["timestamp"]
                )

    async def return_presentation(
        self,
        pres_ex_record: AnonCredsProofRequestContainer,
        requested_credentials: Optional[dict] = None,
    ) -> dict:
        """Return Anoncreds proof request as dict."""

        # If not anoncreds capable, try to use indy handler. This should be removed when
        # indy filter is completely retired
        if not isinstance(self._profile, AskarAnoncredsProfile):
            from ..indy.pres_exch_handler import IndyPresExchHandler

            handler = IndyPresExchHandler(self._profile)
            return await handler.return_presentation(
                pres_ex_record, requested_credentials
            )

        requested_credentials = requested_credentials or {}
        proof_request = pres_ex_record.get_ac_proof_request()
        non_revoc_intervals = extract_non_revocation_intervals_from_proof_request(
            proof_request
        )

        requested_referents = self._get_requested_referents(
            proof_request, requested_credentials, non_revoc_intervals
        )

        credentials = await self._get_credentials(requested_referents)
        self._remove_superfluous_timestamps(requested_credentials, credentials)

        schemas, cred_defs, revocation_registries = await self._get_ledger_objects(
            credentials
        )

        rev_lists = await self._get_revocation_lists(requested_referents, credentials)

        revocation_states = await self._get_revocation_states(
            revocation_registries, credentials, rev_lists
        )

        self._set_timestamps(requested_credentials, requested_referents)

        proof_json = await self.holder.create_presentation(
            proof_request,
            requested_credentials,
            schemas,
            cred_defs,
            revocation_states,
        )
        proof = json.loads(proof_json)
        return proof
