"""Classes to manage presentations."""

import json
import logging
import time

from typing import Tuple

from ....connections.models.conn_record import ConnRecord
from ....core.error import BaseError
from ....core.profile import Profile
from ....indy.holder import IndyHolder, IndyHolderError
from ....indy.sdk.models.predicate import Predicate
from ....indy.sdk.models.xform import indy_proof_req2non_revoc_intervals
from ....indy.util import generate_pr_nonce
from ....indy.verifier import IndyVerifier
from ....ledger.base import BaseLedger
from ....messaging.decorators.attach_decorator import AttachDecorator
from ....messaging.responder import BaseResponder
from ....messaging.util import canon
from ....revocation.models.revocation_registry import RevocationRegistry
from ....storage.error import StorageNotFoundError

from .models.pres_exchange import V20PresExRecord
from .message_types import ATTACHMENT_FORMAT, PRES_20_REQUEST, PRES_20
from .messages.pres import V20Pres
from .messages.pres_ack import V20PresAck
from .messages.pres_format import V20PresFormat
from .messages.pres_problem_report import V20PresProblemReport, ProblemReportReason
from .messages.pres_proposal import V20PresProposal
from .messages.pres_request import V20PresRequest

LOGGER = logging.getLogger(__name__)


class V20PresManagerError(BaseError):
    """Presentation error."""


class V20PresManager:
    """Class for managing presentations."""

    def __init__(self, profile: Profile):
        """
        Initialize a V20PresManager.

        Args:
            profile: The profile instance for this presentation manager
        """

        self._profile = profile

    async def create_exchange_for_proposal(
        self,
        connection_id: str,
        pres_proposal_message: V20PresProposal,
        auto_present: bool = None,
    ):
        """
        Create a presentation exchange record for input presentation proposal.

        Args:
            connection_id: connection identifier
            pres_proposal_message: presentation proposal to serialize
                to exchange record
            auto_present: whether to present proof upon receiving proof request
                (default to configuration setting)

        Returns:
            Presentation exchange record, created

        """
        pres_ex_record = V20PresExRecord(
            connection_id=connection_id,
            thread_id=pres_proposal_message._thread_id,
            initiator=V20PresExRecord.INITIATOR_SELF,
            role=V20PresExRecord.ROLE_PROVER,
            state=V20PresExRecord.STATE_PROPOSAL_SENT,
            pres_proposal=pres_proposal_message.serialize(),
            auto_present=auto_present,
            trace=(pres_proposal_message._trace is not None),
        )
        async with self._profile.session() as session:
            await pres_ex_record.save(
                session, reason="create v2.0 presentation proposal"
            )

        return pres_ex_record

    async def receive_pres_proposal(
        self, message: V20PresProposal, conn_record: ConnRecord
    ):
        """
        Receive a presentation proposal from message in context on manager creation.

        Returns:
            Presentation exchange record, created

        """
        pres_ex_record = V20PresExRecord(
            connection_id=conn_record.connection_id,
            thread_id=message._thread_id,
            initiator=V20PresExRecord.INITIATOR_EXTERNAL,
            role=V20PresExRecord.ROLE_VERIFIER,
            state=V20PresExRecord.STATE_PROPOSAL_RECEIVED,
            pres_proposal=message.serialize(),
            trace=(message._trace is not None),
        )
        async with self._profile.session() as session:
            await pres_ex_record.save(
                session, reason="receive v2.0 presentation request"
            )

        return pres_ex_record

    async def create_bound_request(
        self,
        pres_ex_record: V20PresExRecord,
        name: str = None,
        version: str = None,
        nonce: str = None,
        comment: str = None,
    ):
        """
        Create a presentation request bound to a proposal.

        Args:
            pres_ex_record: Presentation exchange record for which
                to create presentation request
            name: name to use in presentation request (None for default)
            version: version to use in presentation request (None for default)
            nonce: nonce to use in presentation request (None to generate)
            comment: Optional human-readable comment pertaining to request creation

        Returns:
            A tuple (updated presentation exchange record, presentation request message)

        """
        indy_proof_request = V20PresProposal.deserialize(
            pres_ex_record.pres_proposal
        ).attachment(
            V20PresFormat.Format.INDY
        )  # will change for DIF

        indy_proof_request["name"] = name or "proof-request"
        indy_proof_request["version"] = version or "1.0"
        indy_proof_request["nonce"] = nonce or await generate_pr_nonce()

        pres_request_message = V20PresRequest(
            comment=comment,
            will_confirm=True,
            formats=[
                V20PresFormat(
                    attach_id="indy",
                    format_=ATTACHMENT_FORMAT[PRES_20_REQUEST][
                        V20PresFormat.Format.INDY.api
                    ],
                )
            ],
            request_presentations_attach=[
                AttachDecorator.data_base64(
                    mapping=indy_proof_request,
                    ident="indy",
                )
            ],
        )
        pres_request_message._thread = {"thid": pres_ex_record.thread_id}
        pres_request_message.assign_trace_decorator(
            self._profile.settings, pres_ex_record.trace
        )

        pres_ex_record.thread_id = pres_request_message._thread_id
        pres_ex_record.state = V20PresExRecord.STATE_REQUEST_SENT
        pres_ex_record.pres_request = pres_request_message.serialize()
        async with self._profile.session() as session:
            await pres_ex_record.save(
                session, reason="create (bound) v2.0 presentation request"
            )

        return pres_ex_record, pres_request_message

    async def create_exchange_for_request(
        self, connection_id: str, pres_request_message: V20PresRequest
    ):
        """
        Create a presentation exchange record for input presentation request.

        Args:
            connection_id: connection identifier
            pres_request_message: presentation request to use in creating
                exchange record, extracting indy proof request and thread id

        Returns:
            Presentation exchange record, updated

        """
        pres_ex_record = V20PresExRecord(
            connection_id=connection_id,
            thread_id=pres_request_message._thread_id,
            initiator=V20PresExRecord.INITIATOR_SELF,
            role=V20PresExRecord.ROLE_VERIFIER,
            state=V20PresExRecord.STATE_REQUEST_SENT,
            pres_request=pres_request_message.serialize(),
            trace=(pres_request_message._trace is not None),
        )
        async with self._profile.session() as session:
            await pres_ex_record.save(
                session, reason="create (free) v2.0 presentation request"
            )

        return pres_ex_record

    async def receive_pres_request(self, pres_ex_record: V20PresExRecord):
        """
        Receive a presentation request.

        Args:
            pres_ex_record: presentation exchange record with request to receive

        Returns:
            The presentation exchange record, updated

        """
        pres_ex_record.state = V20PresExRecord.STATE_REQUEST_RECEIVED
        async with self._profile.session() as session:
            await pres_ex_record.save(
                session, reason="receive v2.0 presentation request"
            )

        return pres_ex_record

    async def create_pres(
        self,
        pres_ex_record: V20PresExRecord,
        requested_credentials: dict,
        comment: str = None,
        *,
        format_: V20PresFormat.Format = None,
    ) -> Tuple[V20PresExRecord, V20Pres]:
        """
        Create a presentation.

        Args:
            pres_ex_record: record to update
            requested_credentials: indy formatted requested_credentials
            comment: optional human-readable comment
            format_: presentation format

        Example `requested_credentials` format, mapping proof request referents (uuid)
        to wallet referents (cred id):

        ::

            {
                "self_attested_attributes": {
                    "j233ffbc-bd35-49b1-934f-51e083106f6d": "value"
                },
                "requested_attributes": {
                    "6253ffbb-bd35-49b3-934f-46e083106f6c": {
                        "cred_id": "5bfa40b7-062b-4ae0-a251-a86c87922c0e",
                        "revealed": true
                    }
                },
                "requested_predicates": {
                    "bfc8a97d-60d3-4f21-b998-85eeabe5c8c0": {
                        "cred_id": "5bfa40b7-062b-4ae0-a251-a86c87922c0e"
                    }
                }
            }

        Returns:
            A tuple (updated presentation exchange record, presentation message)

        """
        assert format_ in (None, V20PresFormat.Format.INDY)  # until DIF support

        # Get all credentials for this presentation
        holder = self._profile.inject(IndyHolder)
        credentials = {}

        # extract credential ids and non_revoked
        requested_referents = {}
        proof_request = V20PresRequest.deserialize(
            pres_ex_record.pres_request
        ).attachment(format_)
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

        pres_message = V20Pres(
            comment=comment,
            formats=[
                V20PresFormat(
                    attach_id="indy",
                    format_=ATTACHMENT_FORMAT[PRES_20][V20PresFormat.Format.INDY.api],
                )
            ],
            presentations_attach=[
                AttachDecorator.data_base64(mapping=indy_proof, ident="indy")
            ],
        )

        pres_message._thread = {"thid": pres_ex_record.thread_id}
        pres_message.assign_trace_decorator(
            self._profile.settings, pres_ex_record.trace
        )

        # save presentation exchange state
        pres_ex_record.state = V20PresExRecord.STATE_PRESENTATION_SENT
        pres_ex_record.pres = V20Pres(
            formats=[
                V20PresFormat(
                    attach_id="indy",
                    format_=ATTACHMENT_FORMAT[PRES_20][V20PresFormat.Format.INDY.api],
                ),
            ],
            presentations_attach=[
                AttachDecorator.data_base64(
                    mapping=indy_proof,
                    ident="indy",
                )
            ],
        ).serialize()
        async with self._profile.session() as session:
            await pres_ex_record.save(session, reason="create v2.0 presentation")

        return pres_ex_record, pres_message

    async def receive_pres(self, message: V20Pres, conn_record: ConnRecord):
        """
        Receive a presentation, from message in context on manager creation.

        Returns:
            presentation exchange record, retrieved and updated

        """

        def _check_proof_vs_proposal():
            """Check for bait and switch in presented values vs. proposal request."""
            proof_req = V20PresRequest.deserialize(
                pres_ex_record.pres_request
            ).attachment(
                V20PresFormat.Format.INDY
            )  # will change for DIF

            # revealed attrs
            for reft, attr_spec in proof["requested_proof"]["revealed_attrs"].items():
                proof_req_attr_spec = proof_req["requested_attributes"].get(reft)
                if not proof_req_attr_spec:
                    raise V20PresManagerError(
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
                    raise V20PresManagerError(
                        f"Presented attribute {reft} does not satisfy proof request "
                        f"restrictions {req_restrictions}"
                    )

            # revealed attr groups
            for reft, attr_spec in (
                proof["requested_proof"].get("revealed_attr_groups", {}).items()
            ):
                proof_req_attr_spec = proof_req["requested_attributes"].get(reft)
                if not proof_req_attr_spec:
                    raise V20PresManagerError(
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
                    raise V20PresManagerError(
                        f"Presented attr group {reft} does not satisfy proof request "
                        f"restrictions {req_restrictions}"
                    )

            # predicate bounds
            for reft, pred_spec in proof["requested_proof"]["predicates"].items():
                proof_req_pred_spec = proof_req["requested_predicates"].get(reft)
                if not proof_req_pred_spec:
                    raise V20PresManagerError(
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
                        raise V20PresManagerError(
                            f"Presentation predicate on {req_name} "
                            "mismatches proposal request"
                        )
                    break
                else:
                    raise V20PresManagerError(
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
                    raise V20PresManagerError(
                        f"Presented predicate {reft} does not satisfy proof request "
                        f"restrictions {req_restrictions}"
                    )

        proof = message.attachment(V20PresFormat.Format.INDY)

        thread_id = message._thread_id
        conn_id_filter = (
            None
            if conn_record is None
            else {"connection_id": conn_record.connection_id}
        )
        async with self._profile.session() as session:
            try:
                pres_ex_record = await V20PresExRecord.retrieve_by_tag_filter(
                    session, {"thread_id": thread_id}, conn_id_filter
                )
            except StorageNotFoundError:
                # Proof req not bound to any connection: requests_attach in OOB msg
                pres_ex_record = await V20PresExRecord.retrieve_by_tag_filter(
                    session, {"thread_id": thread_id}, None
                )

        _check_proof_vs_proposal()

        pres_ex_record.pres = message.serialize()
        pres_ex_record.state = V20PresExRecord.STATE_PRESENTATION_RECEIVED

        async with self._profile.session() as session:
            await pres_ex_record.save(session, reason="receive v2.0 presentation")

        return pres_ex_record

    async def verify_pres(self, pres_ex_record: V20PresExRecord):
        """
        Verify a presentation.

        Args:
            pres_ex_record: presentation exchange record
                with presentation request and presentation to verify

        Returns:
            presentation exchange record, updated

        """
        pres_request_msg = V20PresRequest.deserialize(pres_ex_record.pres_request)
        indy_proof_request = pres_request_msg.attachment(V20PresFormat.Format.INDY)
        indy_proof = V20Pres.deserialize(pres_ex_record.pres).attachment(
            V20PresFormat.Format.INDY
        )  # will change for DIF

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
        pres_ex_record.state = V20PresExRecord.STATE_DONE

        async with self._profile.session() as session:
            await pres_ex_record.save(session, reason="verify v2.0 presentation")

        if pres_request_msg.will_confirm:
            await self.send_pres_ack(pres_ex_record)

        return pres_ex_record

    async def send_pres_ack(self, pres_ex_record: V20PresExRecord):
        """
        Send acknowledgement of presentation receipt.

        Args:
            pres_ex_record: presentation exchange record with thread id

        """
        responder = self._profile.inject(BaseResponder, required=False)

        if responder:
            pres_ack_message = V20PresAck()
            pres_ack_message._thread = {"thid": pres_ex_record.thread_id}
            pres_ack_message.assign_trace_decorator(
                self._profile.settings, pres_ex_record.trace
            )

            await responder.send_reply(
                pres_ack_message,
                connection_id=pres_ex_record.connection_id,
            )
        else:
            LOGGER.warning(
                "Configuration has no BaseResponder: cannot ack presentation on %s",
                pres_ex_record.thread_id,
            )

    async def receive_pres_ack(self, message: V20PresAck, conn_record: ConnRecord):
        """
        Receive a presentation ack, from message in context on manager creation.

        Returns:
            presentation exchange record, retrieved and updated

        """
        async with self._profile.session() as session:
            pres_ex_record = await V20PresExRecord.retrieve_by_tag_filter(
                session,
                {"thread_id": message._thread_id},
                {"connection_id": conn_record.connection_id},
            )

            pres_ex_record.state = V20PresExRecord.STATE_DONE

            await pres_ex_record.save(session, reason="receive v2.0 presentation ack")

        return pres_ex_record

    async def create_problem_report(
        self,
        pres_ex_record: V20PresExRecord,
        description: str,
    ):
        """
        Update pres ex record; create and return problem report.

        Returns:
            problem report

        """
        pres_ex_record.state = V20PresExRecord.STATE_ABANDONED
        async with self._profile.session() as session:
            await pres_ex_record.save(session, reason="created problem report")

        report = V20PresProblemReport(
            description={
                "en": description,
                "code": ProblemReportReason.ABANDONED.value,
            }
        )
        report.assign_thread_id(pres_ex_record.thread_id)

        return report

    async def receive_problem_report(
        self, message: V20PresProblemReport, connection_id: str
    ):
        """
        Receive problem report.

        Returns:
            presentation exchange record, retrieved and updated

        """
        # FIXME use transaction, fetch for_update
        async with self._profile.session() as session:
            pres_ex_record = await (
                V20PresExRecord.retrieve_by_tag_filter(
                    session,
                    {"thread_id": message._thread_id},
                    {"connection_id": connection_id},
                )
            )

            pres_ex_record.state = V20PresExRecord.STATE_ABANDONED
            code = message.description.get("code", ProblemReportReason.ABANDONED.value)
            pres_ex_record.error_msg = f"{code}: {message.description.get('en', code)}"
            await pres_ex_record.save(session, reason="received problem report")

        return pres_ex_record
