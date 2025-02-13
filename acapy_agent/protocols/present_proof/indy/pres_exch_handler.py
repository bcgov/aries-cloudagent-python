"""Utilities for dif presentation exchange attachment."""

import json
import logging
import time
from typing import Optional, Tuple

from ....core.error import BaseError
from ....core.profile import Profile
from ....indy.holder import IndyHolder, IndyHolderError
from ....indy.models.xform import indy_proof_req2non_revoc_intervals
from ....ledger.multiple_ledger.ledger_requests_executor import (
    GET_REVOC_REG_DELTA,
    GET_SCHEMA,
    IndyLedgerRequestsExecutor,
)
from ....multitenant.base import BaseMultitenantManager
from ....revocation.models.revocation_registry import RevocationRegistry
from ..anoncreds.pres_exch_handler import AnonCredsProofRequestContainer

LOGGER = logging.getLogger(__name__)


class IndyPresExchHandlerError(BaseError):
    """Base class for Indy Presentation Exchange related errors."""


class IndyPresExchHandler:
    """Base Presentation Exchange Handler."""

    def __init__(
        self,
        profile: Profile,
    ):
        """Initialize PresExchange Handler."""
        super().__init__()
        self._profile = profile

    async def return_presentation(
        self,
        pres_ex_record: AnonCredsProofRequestContainer,
        requested_credentials: Optional[dict] = None,
    ) -> dict:
        """Return Indy proof request as dict."""
        # Get all credentials for this presentation
        holder = self._profile.inject(IndyHolder)
        credentials = {}
        requested_credentials = requested_credentials or {}

        # extract credential ids and non_revoked
        requested_referents = {}
        proof_request = pres_ex_record.get_ac_proof_request()

        non_revoc_intervals = indy_proof_req2non_revoc_intervals(proof_request)
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
        # extract mapping of presentation referents to credential ids
        for reft in requested_referents:
            credential_id = requested_referents[reft]["cred_id"]
            if credential_id not in credentials:
                credentials[credential_id] = json.loads(
                    await holder.get_credential(credential_id)
                )
        # remove any timestamps that cannot correspond to non-revoc intervals
        for r in ("requested_attributes", "requested_predicates"):
            for reft, req_item in requested_credentials.get(r, {}).items():
                if not credentials[req_item["cred_id"]].get(
                    "rev_reg_id"
                ) and req_item.pop("timestamp", None):
                    LOGGER.info(
                        f"Removed superfluous timestamp from requested_credentials {r} "
                        f"{reft} for non-revocable credential {req_item['cred_id']}"
                    )
        # Get all schemas, credential definitions, and revocation registries in use
        schemas = {}
        cred_defs = {}
        revocation_registries = {}

        for credential in credentials.values():
            schema_id = credential["schema_id"]
            multitenant_mgr = self._profile.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(self._profile)
            else:
                ledger_exec_inst = self._profile.inject(IndyLedgerRequestsExecutor)
            ledger = (
                await ledger_exec_inst.get_ledger_for_identifier(
                    schema_id,
                    txn_record_type=GET_SCHEMA,
                )
            )[1]
            async with ledger:
                if schema_id not in schemas:
                    schemas[schema_id] = await ledger.get_schema(schema_id)
                cred_def_id = credential["cred_def_id"]
                if cred_def_id not in cred_defs:
                    cred_defs[cred_def_id] = await ledger.get_credential_definition(
                        cred_def_id
                    )
                if credential.get("rev_reg_id"):
                    revocation_registry_id = credential["rev_reg_id"]
                    if revocation_registry_id not in revocation_registries:
                        revocation_registries[revocation_registry_id] = (
                            RevocationRegistry.from_definition(
                                await ledger.get_revoc_reg_def(revocation_registry_id),
                                True,
                            )
                        )
        # Get delta with non-revocation interval defined in "non_revoked"
        # of the presentation request or attributes
        epoch_now = int(time.time())
        revoc_reg_deltas = {}
        for precis in requested_referents.values():  # cred_id, non-revoc interval
            credential_id = precis["cred_id"]
            if not credentials[credential_id].get("rev_reg_id"):
                continue
            if "timestamp" in precis:
                continue
            rev_reg_id = credentials[credential_id]["rev_reg_id"]
            multitenant_mgr = self._profile.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(self._profile)
            else:
                ledger_exec_inst = self._profile.inject(IndyLedgerRequestsExecutor)
            ledger = (
                await ledger_exec_inst.get_ledger_for_identifier(
                    rev_reg_id,
                    txn_record_type=GET_REVOC_REG_DELTA,
                )
            )[1]
            async with ledger:
                reft_non_revoc_interval = precis.get("non_revoked")
                if reft_non_revoc_interval:
                    key = (
                        f"{rev_reg_id}_"
                        f"{reft_non_revoc_interval.get('from', 0)}_"
                        f"{reft_non_revoc_interval.get('to', epoch_now)}"
                    )
                    if key not in revoc_reg_deltas:
                        (delta, delta_timestamp) = await ledger.get_revoc_reg_delta(
                            rev_reg_id,
                            reft_non_revoc_interval.get("from", 0),
                            reft_non_revoc_interval.get("to", epoch_now),
                        )
                        revoc_reg_deltas[key] = (
                            rev_reg_id,
                            credential_id,
                            delta,
                            delta_timestamp,
                        )
                    for stamp_me in requested_referents.values():
                        # often one cred satisfies many requested attrs/preds
                        if stamp_me["cred_id"] == credential_id:
                            stamp_me["timestamp"] = revoc_reg_deltas[key][3]
        # Get revocation states to prove non-revoked
        revocation_states = {}
        for (
            rev_reg_id,
            credential_id,
            delta,
            delta_timestamp,
        ) in revoc_reg_deltas.values():
            if rev_reg_id not in revocation_states:
                revocation_states[rev_reg_id] = {}
            rev_reg = revocation_registries[rev_reg_id]
            tails_local_path = await rev_reg.get_or_fetch_local_tails_path()
            try:
                revocation_states[rev_reg_id][delta_timestamp] = json.loads(
                    await holder.create_revocation_state(
                        credentials[credential_id]["cred_rev_id"],
                        rev_reg.reg_def,
                        delta,
                        delta_timestamp,
                        tails_local_path,
                    )
                )
            except IndyHolderError as e:
                LOGGER.error(
                    f"Failed to create revocation state: {e.error_code}, {e.message}"
                )
                raise e
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
        indy_proof_json = await holder.create_presentation(
            proof_request,
            requested_credentials,
            schemas,
            cred_defs,
            revocation_states,
        )
        indy_proof = json.loads(indy_proof_json)
        return indy_proof

    async def process_pres_identifiers(
        self,
        identifiers: list,
    ) -> Tuple[dict, dict, dict, dict]:
        """Return schemas, cred_defs, rev_reg_defs, rev_reg_entries."""
        schema_ids = []
        cred_def_ids = []

        schemas = {}
        cred_defs = {}
        rev_reg_defs = {}
        rev_reg_entries = {}

        for identifier in identifiers:
            schema_ids.append(identifier["schema_id"])
            cred_def_ids.append(identifier["cred_def_id"])
            multitenant_mgr = self._profile.inject_or(BaseMultitenantManager)
            if multitenant_mgr:
                ledger_exec_inst = IndyLedgerRequestsExecutor(self._profile)
            else:
                ledger_exec_inst = self._profile.inject(IndyLedgerRequestsExecutor)
            ledger = (
                await ledger_exec_inst.get_ledger_for_identifier(
                    identifier["schema_id"],
                    txn_record_type=GET_SCHEMA,
                )
            )[1]
            async with ledger:
                # Build schemas for anoncreds
                if identifier["schema_id"] not in schemas:
                    schemas[identifier["schema_id"]] = await ledger.get_schema(
                        identifier["schema_id"]
                    )

                if identifier["cred_def_id"] not in cred_defs:
                    cred_defs[
                        identifier["cred_def_id"]
                    ] = await ledger.get_credential_definition(identifier["cred_def_id"])

                if identifier.get("rev_reg_id"):
                    if identifier["rev_reg_id"] not in rev_reg_defs:
                        rev_reg_defs[
                            identifier["rev_reg_id"]
                        ] = await ledger.get_revoc_reg_def(identifier["rev_reg_id"])

                    if identifier.get("timestamp"):
                        rev_reg_entries.setdefault(identifier["rev_reg_id"], {})

                        if (
                            identifier["timestamp"]
                            not in rev_reg_entries[identifier["rev_reg_id"]]
                        ):
                            (
                                found_rev_reg_entry,
                                _found_timestamp,
                            ) = await ledger.get_revoc_reg_entry(
                                identifier["rev_reg_id"], identifier["timestamp"]
                            )
                            rev_reg_entries[identifier["rev_reg_id"]][
                                identifier["timestamp"]
                            ] = found_rev_reg_entry
        return (
            schemas,
            cred_defs,
            rev_reg_defs,
            rev_reg_entries,
        )
