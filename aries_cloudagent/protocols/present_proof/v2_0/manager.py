"""Classes to manage presentations."""

import json
import logging
import time

from typing import Tuple

from ....connections.models.conn_record import ConnRecord
from ....core.error import BaseError
from ....core.profile import Profile
from ....indy.holder import IndyHolder, IndyHolderError
from ....indy.util import generate_pr_nonce
from ....indy.verifier import IndyVerifier
from ....ledger.base import BaseLedger
from ....messaging.decorators.attach_decorator import AttachDecorator
from ....messaging.responder import BaseResponder
from ....messaging.util import canon
from ....revocation.models.revocation_registry import RevocationRegistry
from ....storage.error import StorageNotFoundError

from ..indy.predicate import Predicate
from ..indy.xform import indy_proof_req2non_revoc_intervals

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
            auto_present=auto_present,
            trace=(pres_proposal_message._trace is not None),
        )
        for format in pres_proposal_message.formats:
            await V20PresFormat.Format.get(format.format).handler(
                self._profile
            ).create_exchange_for_proposal(pres_ex_record, pres_proposal_message)
        pres_ex_record.pres_proposal = pres_proposal_message.serialize()
        pres_ex_record.state = V20PresExRecord.STATE_PROPOSAL_SENT

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
            trace=(message._trace is not None),
        )

        for format in message.formats:
            await V20PresFormat.Format.get(format.format).handler(
                self._profile
            ).receive_pres_proposal(pres_ex_record, message)
        pres_ex_record.pres_proposal = message.serialize()
        pres_ex_record.state = V20PresExRecord.STATE_PROPOSAL_RECEIVED

        async with self._profile.session() as session:
            await pres_ex_record.save(
                session, reason="receive v2.0 presentation request"
            )

        return pres_ex_record

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
            trace=(pres_request_message._trace is not None),
        )

        for format in pres_request_message.formats:
            await V20PresFormat.Format.get(format.format).handler(
                self._profile
            ).create_exchange_for_request(pres_ex_record, pres_request_message)
        pres_ex_record.pres_request = pres_request_message.serialize()
        pres_ex_record.state = V20PresExRecord.STATE_REQUEST_SENT

        async with self._profile.session() as session:
            await pres_ex_record.save(
                session, reason="create (free) v2.0 presentation request"
            )

        return pres_ex_record

    async def create_bound_request(
        self,
        pres_ex_record: V20PresExRecord,
        request_data: dict = None,
        comment: str = None,
    ):
        """
        Create a presentation request bound to a proposal.

        Args:
            pres_ex_record: Presentation exchange record for which
                to create presentation request
            fmt2filter: Mapping between format and filter
            name: name to use in presentation request (None for default)
            version: version to use in presentation request (None for default)
            nonce: nonce to use in presentation request (None to generate)
            comment: Optional human-readable comment pertaining to request creation

        Returns:
            A tuple (updated presentation exchange record, presentation request message)

        """
        proof_proposal = V20PresProposal.deserialize(pres_ex_record.pres_proposal)
        input_formats = proof_proposal.formats
        request_formats = []
        for format in input_formats:
            pres_exch_format = V20PresFormat.Format.get(format.format)

            if pres_exch_format:
                request_formats.append(
                    await pres_exch_format.handler(self._profile).create_bound_request(
                        pres_ex_record,
                        request_data,
                    )
                )
        if len(request_formats) == 0:
            raise V20PresManagerError(
                "Unable to create presentation request. No supported formats"
            )
        pres_request_message = V20PresRequest(
            comment=comment,
            will_confirm=True,
            formats=[format for (format, _) in request_formats],
            request_presentations_attach=[attach for (_, attach) in request_formats],
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
        request_data: dict,
        *,
        comment: str = None,
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
        proof_request = V20PresRequest.deserialize(pres_ex_record.pres_request)
        input_formats = proof_request.formats
        pres_formats = []
        for format in input_formats:
            pres_exch_format = V20PresFormat.Format.get(format.format)

            if pres_exch_format:
                pres_formats.append(
                    await pres_exch_format.handler(self._profile).create_pres(
                        pres_ex_record,
                        request_data,
                    )
                )
        if len(pres_formats) == 0:
            raise V20PresManagerError(
                "Unable to create presentation. No supported formats"
            )

        pres_message = V20Pres(
            comment=comment,
            formats=[format for (format, _) in pres_formats],
            presentations_attach=[attach for (_, attach) in pres_formats],
        )

        pres_message._thread = {"thid": pres_ex_record.thread_id}
        pres_message.assign_trace_decorator(
            self._profile.settings, pres_ex_record.trace
        )

        # save presentation exchange state
        pres_ex_record.state = V20PresExRecord.STATE_PRESENTATION_SENT
        pres_ex_record.pres = V20Pres(
            formats=[format for (format, _) in pres_formats],
            presentations_attach=[attach for (_, attach) in pres_formats],
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

        input_formats = message.formats
        pres_formats = []
        for format in input_formats:
            pres_format = V20PresFormat.Format.get(format.format)

            if pres_format:
                await pres_format.handler(self._profile).receive_pres(
                    message,
                    pres_ex_record,
                )
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
        input_formats = pres_request_msg.formats
        for format in input_formats:
            pres_exch_format = V20PresFormat.Format.get(format.format)

            if pres_exch_format:
                pres_ex_record = await pres_exch_format.handler(
                    self._profile
                ).verify_pres(
                    pres_ex_record,
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
