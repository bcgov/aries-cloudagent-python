"""V2.0 present-proof indy presentation-exchange format handler."""

import logging

from marshmallow import RAISE
import json
from typing import Mapping, Tuple
import asyncio
import time

from ......cache.base import BaseCache
from ......indy.issuer import IndyIssuer, IndyIssuerRevocationRegistryFullError
from ......indy.holder import IndyHolder, IndyHolderError
from ......indy.util import generate_pr_nonce
from ......indy.verifier import IndyVerifier

from ....indy.proof_request import IndyProofRequestSchema
from ....indy.proof import IndyProofSchema
from ....indy.predicate import Predicate
from ....indy.xform import indy_proof_req2non_revoc_intervals
from ......ledger.base import BaseLedger
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......messaging.util import canon
from ......revocation.models.issuer_rev_reg_record import IssuerRevRegRecord
from ......revocation.models.revocation_registry import RevocationRegistry
from ......revocation.indy import IndyRevocation
from ......storage.base import BaseStorage
from ......storage.error import StorageNotFoundError

from ...message_types import (
    ATTACHMENT_FORMAT,
    PRES_20_REQUEST,
    PRES_20,
    PRES_20_PROPOSAL,
    PRES_20_ACK,
)

from ...messages.pres_ack import V20PresAck
from ...messages.pres_format import V20PresFormat
from ...messages.pres_proposal import V20PresProposal
from ...messages.pres_request import V20PresRequest
from ...messages.pres import V20Pres
from ...models.pres_exchange import V20PresExRecord
from ..handler import V20PresFormatHandler, V20PresFormatError

LOGGER = logging.getLogger(__name__)


class IndyPresExchangeHandler(V20PresFormatHandler):
    """Indy presentation format handler."""

    format = V20PresFormat.Format.INDY

    @classmethod
    def validate_fields(cls, message_type: str, attachment_data: Mapping):
        """Validate attachment data for a specific message type.

        Uses marshmallow schemas to validate if format specific attachment data
        is valid for the specified message type. Only does structural and type
        checks, does not validate if .e.g. the issuer value is valid.


        Args:
            message_type (str): The message type to validate the attachment data for.
                Should be one of the message types as defined in message_types.py
            attachment_data (Mapping): [description]
                The attachment data to valide

        Raises:
            Exception: When the data is not valid.

        """
        mapping = {
            PRES_20_REQUEST: IndyProofRequestSchema,
            PRES_20_PROPOSAL: IndyProofRequestSchema,
            PRES_20: IndyProofSchema,
        }

        # Get schema class
        Schema = mapping[message_type]

        # Validate, throw if not valid
        Schema(unknown=RAISE).load(attachment_data)

    async def create_exchange_for_proposal(
        self,
        pres_ex_record: V20PresExRecord,
        pres_proposal_message: V20PresProposal,
    ) -> None:
        """Create a presentation exchange record for input presentation proposal."""

    async def receive_pres_proposal(
        self,
        pres_ex_record: V20PresExRecord,
        message: V20PresProposal,
    ) -> None:
        """Receive a presentation proposal from message in context on manager creation."""

    async def create_exchange_for_request(
        self,
        pres_ex_record: V20PresExRecord,
        pres_request_message: V20PresRequest,
    ) -> None:
        """Create a presentation exchange record for input presentation request."""

    async def create_bound_request(
        self,
        pres_ex_record: V20PresExRecord,
        request_data: dict = None,
    ) -> Tuple[V20PresFormat, AttachDecorator]:
        """
        Create a presentation request bound to a proposal.

        Args:
            pres_ex_record: Presentation exchange record for which
                to create presentation request
            request_data: Dict 

        Returns:
            A tuple (updated presentation exchange record, presentation request message)

        """
        name = request_data.get("name") or "proof-request"
        version = request_data.get("version") or "1.0"
        nonce = request_data.get("nonce") or await generate_pr_nonce()
        indy_proof_request = V20PresProposal.deserialize(
            pres_ex_record.pres_proposal
        ).attachment(format)

        return self.get_format_data(PRES_20_REQUEST, indy_proof_request)

    async def create_pres(
        self,
        pres_ex_record: V20PresExRecord,
        request_data: dict = None,
    ) -> Tuple[V20PresFormat, AttachDecorator]:
        """Create a presentation."""
        requested_credentials= request_data.get("requested_credentials")
        # Get all credentials for this presentation
        holder = self._profile.inject(IndyHolder)
        credentials = {}

        # extract credential ids and non_revoked
        requested_referents = {}
        proof_request = V20PresRequest.deserialize(
            pres_ex_record.pres_request
        ).attachment(format)
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
        ledger = self._profile.inject(BaseLedger)
        schemas = {}
        cred_defs = {}
        revocation_registries = {}

        async with ledger:
            for credential in credentials.values():
                schema_id = credential["schema_id"]
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
                        revocation_registries[
                            revocation_registry_id
                        ] = RevocationRegistry.from_definition(
                            await ledger.get_revoc_reg_def(revocation_registry_id), True
                        )

        # Get delta with non-revocation interval defined in "non_revoked"
        # of the presentation request or attributes
        epoch_now = int(time.time())

        revoc_reg_deltas = {}
        async with ledger:
            for precis in requested_referents.values():  # cred_id, non-revoc interval
                credential_id = precis["cred_id"]
                if not credentials[credential_id].get("rev_reg_id"):
                    continue
                if "timestamp" in precis:
                    continue
                rev_reg_id = credentials[credential_id]["rev_reg_id"]
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

        for (referent, precis) in requested_referents.items():
            if "timestamp" not in precis:
                continue
            if referent in requested_credentials["requested_attributes"]:
                requested_credentials["requested_attributes"][referent][
                    "timestamp"
                ] = precis["timestamp"]
            if referent in requested_credentials["requested_predicates"]:
                requested_credentials["requested_predicates"][referent][
                    "timestamp"
                ] = precis["timestamp"]

        indy_proof_json = await holder.create_presentation(
            proof_request,
            requested_credentials,
            schemas,
            cred_defs,
            revocation_states,
        )
        indy_proof = json.loads(indy_proof_json)

        return self.get_format_data(PRES_20, indy_proof)

    async def receive_pres(
        self, message: V20Pres, pres_ex_record: V20PresExRecord
    ) -> None:
        """Receive a presentation and check for presented values vs. proposal request."""

        def _check_proof_vs_proposal():
            """Check for bait and switch in presented values vs. proposal request."""
            proof_req = V20PresRequest.deserialize(
                pres_ex_record.pres_request
            ).attachment(format)

            # revealed attrs
            for reft, attr_spec in proof["requested_proof"]["revealed_attrs"].items():
                proof_req_attr_spec = proof_req["requested_attributes"].get(reft)
                if not proof_req_attr_spec:
                    raise V20PresFormatError(
                        f"Presentation referent {reft} not in proposal request"
                    )
                req_restrictions = proof_req_attr_spec.get("restrictions", {})

                name = proof_req_attr_spec["name"]
                proof_value = attr_spec["raw"]
                sub_proof_index = attr_spec["sub_proof_index"]
                schema_id = proof["identifiers"][sub_proof_index]["schema_id"]
                cred_def_id = proof["identifiers"][sub_proof_index]["cred_def_id"]
                criteria = {
                    "schema_id": schema_id,
                    "schema_issuer_did": schema_id.split(":")[-4],
                    "schema_name": schema_id.split(":")[-2],
                    "schema_version": schema_id.split(":")[-1],
                    "cred_def_id": cred_def_id,
                    "issuer_did": cred_def_id.split(":")[-5],
                    f"attr::{name}::value": proof_value,
                }

                if not any(r.items() <= criteria.items() for r in req_restrictions):
                    raise V20PresFormatError(
                        f"Presentation {name}={proof_value} not in proposal value(s)"
                    )

            # revealed attr groups
            for reft, attr_spec in (
                proof["requested_proof"].get("revealed_attr_groups", {}).items()
            ):
                proof_req_attr_spec = proof_req["requested_attributes"].get(reft)
                if not proof_req_attr_spec:
                    raise V20PresFormatError(
                        f"Presentation referent {reft} not in proposal request"
                    )
                req_restrictions = proof_req_attr_spec.get("restrictions", {})
                proof_values = {
                    name: values["raw"] for name, values in attr_spec["values"].items()
                }
                sub_proof_index = attr_spec["sub_proof_index"]
                schema_id = proof["identifiers"][sub_proof_index]["schema_id"]
                cred_def_id = proof["identifiers"][sub_proof_index]["cred_def_id"]
                criteria = {
                    "schema_id": schema_id,
                    "schema_issuer_did": schema_id.split(":")[-4],
                    "schema_name": schema_id.split(":")[-2],
                    "schema_version": schema_id.split(":")[-1],
                    "cred_def_id": cred_def_id,
                    "issuer_did": cred_def_id.split(":")[-5],
                    **{
                        f"attr::{name}::value": value
                        for name, value in proof_values.items()
                    },
                }

                if not any(r.items() <= criteria.items() for r in req_restrictions):
                    raise V20PresFormatError(
                        f"Presentation attr group {proof_values} "
                        "not in proposal value(s)"
                    )

            # predicate bounds
            for reft, pred_spec in proof["requested_proof"]["predicates"].items():
                proof_req_pred_spec = proof_req["requested_predicates"].get(reft)
                if not proof_req_pred_spec:
                    raise V20PresFormatError(
                        f"Presentation referent {reft} not in proposal request"
                    )
                req_name = proof_req_pred_spec["name"]
                req_pred = Predicate.get(proof_req_pred_spec["p_type"])
                req_value = proof_req_pred_spec["p_value"]
                req_restrictions = proof_req_pred_spec.get("restrictions", {})
                sub_proof_index = pred_spec["sub_proof_index"]
                for ge_proof in proof["proof"]["proofs"][sub_proof_index][
                    "primary_proof"
                ]["ge_proofs"]:
                    proof_pred_spec = ge_proof["predicate"]
                    if proof_pred_spec["attr_name"] != canon(req_name):
                        continue
                    if not (
                        Predicate.get(proof_pred_spec["p_type"]) is req_pred
                        and proof_pred_spec["value"] == req_value
                    ):
                        raise V20PresFormatError(
                            f"Presentation predicate on {req_name} "
                            "mismatches proposal request"
                        )
                    break
                else:
                    raise V20PresFormatError(
                        f"Proposed request predicate on {req_name} not in presentation"
                    )

                schema_id = proof["identifiers"][sub_proof_index]["schema_id"]
                cred_def_id = proof["identifiers"][sub_proof_index]["cred_def_id"]
                criteria = {
                    "schema_id": schema_id,
                    "schema_issuer_did": schema_id.split(":")[-4],
                    "schema_name": schema_id.split(":")[-2],
                    "schema_version": schema_id.split(":")[-1],
                    "cred_def_id": cred_def_id,
                    "issuer_did": cred_def_id.split(":")[-5],
                }

                if not any(r.items() <= criteria.items() for r in req_restrictions):
                    raise V20PresFormatError(
                        f"Presentation predicate {reft} differs from proposal request"
                    )

        proof = message.attachment(format)
        _check_proof_vs_proposal()

    async def verify_pres(self, pres_ex_record: V20PresExRecord) -> V20PresExRecord:
        """
        Verify a presentation.

        Args:
            pres_ex_record: presentation exchange record
                with presentation request and presentation to verify

        Returns:
            presentation exchange record, updated

        """
        pres_request_msg = V20PresRequest.deserialize(pres_ex_record.pres_request)
        indy_proof_request = pres_request_msg.attachment(format)
        indy_proof = V20Pres.deserialize(pres_ex_record.pres).attachment(format)

        schema_ids = []
        cred_def_ids = []

        schemas = {}
        cred_defs = {}
        rev_reg_defs = {}
        rev_reg_entries = {}

        identifiers = indy_proof["identifiers"]
        ledger = self._profile.inject(BaseLedger)
        async with ledger:
            for identifier in identifiers:
                schema_ids.append(identifier["schema_id"])
                cred_def_ids.append(identifier["cred_def_id"])

                # Build schemas for anoncreds
                if identifier["schema_id"] not in schemas:
                    schemas[identifier["schema_id"]] = await ledger.get_schema(
                        identifier["schema_id"]
                    )

                if identifier["cred_def_id"] not in cred_defs:
                    cred_defs[
                        identifier["cred_def_id"]
                    ] = await ledger.get_credential_definition(
                        identifier["cred_def_id"]
                    )

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

        verifier = self._profile.inject(IndyVerifier)
        pres_ex_record.verified = json.dumps(  # tag: needs string value
            await verifier.verify_presentation(
                indy_proof_request,
                indy_proof,
                schemas,
                cred_defs,
                rev_reg_defs,
                rev_reg_entries,
            )
        )
        return pres_ex_record