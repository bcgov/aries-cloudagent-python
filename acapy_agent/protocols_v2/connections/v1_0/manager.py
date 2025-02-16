"""Classes to manage connections."""

import logging
import warnings
from typing import Optional, Sequence, Tuple, Union, cast

from ....connections.base_manager import BaseConnectionManager
from ....connections.models.conn_record import ConnRecord
from ....connections.models.connection_target import ConnectionTarget
from ....core.error import BaseError
from ....core.oob_processor import OobMessageProcessor
from ....core.profile import Profile
from ....messaging.responder import BaseResponder
from ....messaging.valid import IndyDID
from ....storage.error import StorageNotFoundError
from ....transport.inbound.receipt import MessageReceipt
from ....wallet.base import BaseWallet
from ....wallet.did_method import SOV
from ....wallet.key_type import ED25519
from ....protocols.coordinate_mediation.v1_0.manager import MediationManager
from .message_types import ARIES_PROTOCOL as CONN_PROTO
from .messages.connection_invitation import ConnectionInvitation
from .messages.connection_request import ConnectionRequest
from .messages.connection_response import ConnectionResponse
from .messages.problem_report import ConnectionProblemReport, ProblemReportReason
from .models.connection_detail import ConnectionDetail


class ConnectionManagerError(BaseError):
    """Connection error."""


class ConnectionManager(BaseConnectionManager):
    """Class for managing connections."""

    def __init__(self, profile: Profile):
        """Initialize a ConnectionManager.

        Args:
            profile: The profile for this connection manager
        """
        self._profile = profile
        self._logger = logging.getLogger(__name__)
        super().__init__(self._profile)

    @property
    def profile(self) -> Profile:
        """Accessor for the current profile.

        Returns:
            The profile for this connection manager

        """
        return self._profile

    def deprecation_warning(self):
        """Log a deprecation warning."""
        warnings.warn(
            "Aries RFC 0160: Connection Protocol is deprecated and support will be "
            "removed in a future version; use RFC 0023: DID Exchange instead.",
            DeprecationWarning,
        )
        self._logger.warning(
            "Aries RFC 0160: Connection Protocol is deprecated and support will be "
            "removed in a future version; use RFC 0023: DID Exchange instead."
        )

    async def create_invitation(
        self,
        my_label: Optional[str] = None,
        my_endpoint: Optional[str] = None,
        auto_accept: Optional[bool] = None,
        public: bool = False,
        multi_use: bool = False,
        alias: Optional[str] = None,
        routing_keys: Optional[Sequence[str]] = None,
        recipient_keys: Optional[Sequence[str]] = None,
        metadata: Optional[dict] = None,
        mediation_id: Optional[str] = None,
    ) -> Tuple[ConnRecord, ConnectionInvitation]:
        """Generate new connection invitation.

        This interaction represents an out-of-band communication channel. In the future
        and in practice, these sort of invitations will be received over any number of
        channels such as SMS, Email, QR Code, NFC, etc.

        Structure of an invite message:

        ::

            {
                "@type": "https://didcomm.org/connections/1.0/invitation",
                "label": "Alice",
                "did": "did:sov:QmWbsNYhMrjHiqZDTUTEJs"
            }

        Or, in the case of a peer DID:

        ::

            {
                "@type": "https://didcomm.org/connections/1.0/invitation",
                "label": "Alice",
                "did": "did:peer:oiSqsNYhMrjHiqZDTUthsw",
                "recipient_keys": ["8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"],
                "service_endpoint": "https://example.com/endpoint"
                "routing_keys": ["9EH5gYEeNc3z7PYXmd53d5x6qAfCNrqQqEB4nS7Zfu6K"],
            }

        Args:
            my_label: label for this connection
            my_endpoint: endpoint where other party can reach me
            auto_accept: auto-accept a corresponding connection request
                (None to use config)
            public: set to create an invitation from the public DID
            multi_use: set to True to create an invitation for multiple use
            alias: optional alias to apply to connection for later use
            routing_keys: optional list of routing keys for the invitation
            recipient_keys: optional list of recipient keys for the invitation
            metadata: optional metadata to include in the connection record
            mediation_id: optional mediation ID for the connection

        Returns:
            A tuple of the new `ConnRecord` and `ConnectionInvitation` instances

        Raises:
            ConnectionManagerError: if public invitations are not enabled or
                no public DID is available

        """
        self.deprecation_warning()
        # Mediation Record can still be None after this operation if no
        # mediation id passed and no default
        mediation_record = await self._route_manager.mediation_record_if_id(
            self.profile,
            mediation_id,
            or_default=True,
        )
        image_url = self.profile.context.settings.get("image_url")
        invitation = None
        connection = None

        invitation_mode = ConnRecord.INVITATION_MODE_ONCE
        if multi_use:
            invitation_mode = ConnRecord.INVITATION_MODE_MULTI

        if not my_label:
            my_label = self.profile.settings.get("default_label")

        accept = (
            ConnRecord.ACCEPT_AUTO
            if (
                auto_accept
                or (
                    auto_accept is None
                    and self.profile.settings.get("debug.auto_accept_requests")
                )
            )
            else ConnRecord.ACCEPT_MANUAL
        )

        if recipient_keys:
            # TODO: register recipient keys for relay
            # TODO: check that recipient keys are in wallet
            invitation_key = recipient_keys[0]  # TODO first key appropriate?
        else:
            # Create and store new invitation key
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                invitation_signing_key = await wallet.create_signing_key(key_type=ED25519)
            invitation_key = invitation_signing_key.verkey
            recipient_keys = [invitation_key]

        if public:
            if not self.profile.settings.get("public_invites"):
                raise ConnectionManagerError("Public invitations are not enabled")

            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                public_did = await wallet.get_public_did()
            if not public_did:
                raise ConnectionManagerError(
                    "Cannot create public invitation with no public DID"
                )

            # FIXME - allow ledger instance to format public DID with prefix?
            public_did_did = public_did.did
            if bool(IndyDID.PATTERN.match(public_did_did)):
                public_did_did = f"did:sov:{public_did.did}"

            invitation = ConnectionInvitation(
                label=my_label, did=public_did_did, image_url=image_url
            )

            connection = ConnRecord(  # create connection record
                invitation_key=public_did.verkey,
                invitation_msg_id=invitation._id,
                invitation_mode=invitation_mode,
                their_role=ConnRecord.Role.REQUESTER.rfc23,
                state=ConnRecord.State.INVITATION.rfc23,
                accept=accept,
                alias=alias,
                connection_protocol=CONN_PROTO,
            )

            async with self.profile.session() as session:
                await connection.save(session, reason="Created new invitation")

            # Add mapping for multitenant relaying.
            # Mediation of public keys is not supported yet
            await self._route_manager.route_verkey(self.profile, public_did.verkey)

        else:
            # Create connection record
            connection = ConnRecord(
                invitation_key=invitation_key,  # TODO: determine correct key to use
                their_role=ConnRecord.Role.REQUESTER.rfc160,
                state=ConnRecord.State.INVITATION.rfc160,
                accept=accept,
                invitation_mode=invitation_mode,
                alias=alias,
                connection_protocol=CONN_PROTO,
            )
            async with self.profile.session() as session:
                await connection.save(session, reason="Created new invitation")

            await self._route_manager.route_invitation(
                self.profile, connection, mediation_record
            )
            routing_keys, routing_endpoint = await self._route_manager.routing_info(
                self.profile,
                mediation_record,
            )
            my_endpoint = (
                routing_endpoint
                or my_endpoint
                or cast(str, self.profile.settings.get("default_endpoint"))
            )

            # Create connection invitation message
            # Note: Need to split this into two stages
            # to support inbound routing of invites
            # Would want to reuse create_did_document and convert the result
            invitation = ConnectionInvitation(
                label=my_label,
                recipient_keys=recipient_keys,
                routing_keys=routing_keys,
                endpoint=my_endpoint,
                image_url=image_url,
            )

        async with self.profile.session() as session:
            await connection.attach_invitation(session, invitation)

            if metadata:
                for key, value in metadata.items():
                    await connection.metadata_set(session, key, value)

        return connection, invitation

    async def receive_invitation(
        self,
        invitation: ConnectionInvitation,
        their_public_did: Optional[str] = None,
        auto_accept: Optional[bool] = None,
        alias: Optional[str] = None,
        mediation_id: Optional[str] = None,
    ) -> ConnRecord:
        """Create a new connection record to track a received invitation.

        Args:
            invitation: The `ConnectionInvitation` to store
            their_public_did: The public DID of the inviting party (optional)
            auto_accept: Set to True to auto-accept the invitation, False to manually
                accept, or None to use the default setting from the configuration
                (optional)
            alias: An optional alias to set on the connection record (optional)
            mediation_id: The mediation ID to associate with the connection (optional)

        Returns:
            The new `ConnRecord` instance representing the connection

        Raises:
            ConnectionManagerError: If the invitation is missing recipient keys or an
                endpoint

        """
        self.deprecation_warning()
        if not invitation.did:
            if not invitation.recipient_keys:
                raise ConnectionManagerError(
                    "Invitation must contain recipient key(s)",
                    error_code=ProblemReportReason.MISSING_RECIPIENT_KEYS.value,
                )
            if not invitation.endpoint:
                raise ConnectionManagerError(
                    "Invitation must contain an endpoint",
                    error_code=ProblemReportReason.MISSING_ENDPOINT.value,
                )
        accept = (
            ConnRecord.ACCEPT_AUTO
            if (
                auto_accept
                or (
                    auto_accept is None
                    and self.profile.settings.get("debug.auto_accept_invites")
                )
            )
            else ConnRecord.ACCEPT_MANUAL
        )
        # Create connection record
        connection = ConnRecord(
            invitation_key=invitation.recipient_keys and invitation.recipient_keys[0],
            their_label=invitation.label,
            invitation_msg_id=invitation._id,
            their_role=ConnRecord.Role.RESPONDER.rfc160,
            state=ConnRecord.State.INVITATION.rfc160,
            accept=accept,
            alias=alias,
            their_public_did=their_public_did,
            connection_protocol=CONN_PROTO,
        )

        async with self.profile.session() as session:
            await connection.save(
                session,
                reason="Created new connection record from invitation",
                log_params={"invitation": invitation, "their_label": invitation.label},
            )

            # Save the invitation for later processing
            await connection.attach_invitation(session, invitation)

        await self._route_manager.save_mediator_for_connection(
            self.profile, connection, mediation_id=mediation_id
        )

        if connection.accept == ConnRecord.ACCEPT_AUTO:
            request = await self.create_request(connection, mediation_id=mediation_id)
            responder = self.profile.inject_or(BaseResponder)
            if responder:
                await responder.send(request, connection_id=connection.connection_id)
                # refetch connection for accurate state
                async with self.profile.session() as session:
                    connection = await ConnRecord.retrieve_by_id(
                        session, connection.connection_id
                    )
        else:
            self._logger.debug("Connection invitation will await acceptance")
        return connection

    async def create_request(
        self,
        connection: ConnRecord,
        my_label: Optional[str] = None,
        my_endpoint: Optional[str] = None,
        mediation_id: Optional[str] = None,
    ) -> ConnectionRequest:
        """Create a new connection request for a previously-received invitation.

        Args:
            connection: The `ConnRecord` representing the invitation to accept
            my_label: My label
            my_endpoint: My endpoint
            mediation_id: The record id for mediation

        Returns:
            A new `ConnectionRequest` message to send to the other agent

        """
        self.deprecation_warning()

        mediation_records = await self._route_manager.mediation_records_for_connection(
            self.profile,
            connection,
            mediation_id,
            or_default=True,
        )

        if connection.my_did:
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                my_info = await wallet.get_local_did(connection.my_did)
        else:
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                # Create new DID for connection
                my_info = await wallet.create_local_did(SOV, ED25519)
            connection.my_did = my_info.did

        # Idempotent; if routing has already been set up, no action taken
        await self._route_manager.route_connection_as_invitee(
            self.profile, connection, mediation_records
        )

        # Create connection request message
        if my_endpoint:
            my_endpoints = [my_endpoint]
        else:
            my_endpoints = []
            default_endpoint = self.profile.settings.get("default_endpoint")
            if default_endpoint:
                my_endpoints.append(default_endpoint)
            my_endpoints.extend(self.profile.settings.get("additional_endpoints", []))

        did_doc = await self.create_did_document(
            my_info,
            my_endpoints,
            mediation_records=mediation_records,
        )

        if not my_label:
            my_label = self.profile.settings.get("default_label")
        request = ConnectionRequest(
            label=my_label,
            connection=ConnectionDetail(did=connection.my_did, did_doc=did_doc),
            image_url=self.profile.settings.get("image_url"),
        )
        request.assign_thread_id(thid=request._id, pthid=connection.invitation_msg_id)

        # Update connection state
        connection.request_id = request._id
        connection.state = ConnRecord.State.REQUEST.rfc160

        async with self.profile.session() as session:
            await connection.save(session, reason="Created connection request")

        return request

    async def receive_request(
        self,
        request: ConnectionRequest,
        receipt: MessageReceipt,
    ) -> ConnRecord:
        """Receive and store a connection request.

        Args:
            request: The `ConnectionRequest` to accept
            receipt: The message receipt

        Returns:
            The new or updated `ConnRecord` instance

        """
        self.deprecation_warning()
        ConnRecord.log_state(
            "Receiving connection request",
            {"request": request},
            settings=self.profile.settings,
        )

        connection = None
        connection_key = None
        my_info = None

        # Determine what key will need to sign the response
        if receipt.recipient_did_public:
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                my_info = await wallet.get_local_did(receipt.recipient_did)
            connection_key = my_info.verkey
        else:
            connection_key = receipt.recipient_verkey
            try:
                async with self.profile.session() as session:
                    connection = await ConnRecord.retrieve_by_invitation_key(
                        session=session,
                        invitation_key=connection_key,
                        their_role=ConnRecord.Role.REQUESTER.rfc160,
                    )
            except StorageNotFoundError:
                raise ConnectionManagerError(
                    "No invitation found for pairwise connection "
                    f"in state {ConnRecord.State.INVITATION.rfc160}: "
                    "a prior connection request may have updated the connection state",
                    error_code=ProblemReportReason.REQUEST_NOT_ACCEPTED.value,
                )

        invitation = None
        if connection:
            async with self.profile.session() as session:
                invitation = await connection.retrieve_invitation(session)
            connection_key = connection.invitation_key
            ConnRecord.log_state(
                "Found invitation",
                {"invitation": invitation},
                settings=self.profile.settings,
            )

            if connection.is_multiuse_invitation:
                async with self.profile.session() as session:
                    wallet = session.inject(BaseWallet)
                    my_info = await wallet.create_local_did(SOV, ED25519)

                new_connection = ConnRecord(
                    invitation_key=connection_key,
                    my_did=my_info.did,
                    state=ConnRecord.State.REQUEST.rfc160,
                    accept=connection.accept,
                    their_role=connection.their_role,
                    connection_protocol=CONN_PROTO,
                )
                async with self.profile.session() as session:
                    await new_connection.save(
                        session,
                        reason=(
                            "Received connection request from multi-use invitation DID"
                        ),
                        event=False,
                    )

                # Transfer metadata from multi-use to new connection
                # Must come after save so there's an ID to associate with metadata
                async with self.profile.session() as session:
                    for key, value in (
                        await connection.metadata_get_all(session)
                    ).items():
                        await new_connection.metadata_set(session, key, value)

                connection = new_connection

        conn_did_doc = request.connection.did_doc
        if not conn_did_doc:
            raise ConnectionManagerError(
                "No DIDDoc provided; cannot connect to public DID",
            )
        if request.connection.did != conn_did_doc.did:
            raise ConnectionManagerError(
                "Connection DID does not match DIDDoc id",
                error_code=ProblemReportReason.REQUEST_NOT_ACCEPTED.value,
            )
        await self.store_did_document(conn_did_doc)

        if connection:
            connection.their_label = request.label
            connection.their_did = request.connection.did
            connection.state = ConnRecord.State.REQUEST.rfc160
            async with self.profile.session() as session:
                # force emitting event that would be ignored for multi-use invitations
                # since the record is not new, and the state was not updated
                await connection.save(
                    session,
                    reason="Received connection request from invitation",
                    event=True,
                )
        elif not self.profile.settings.get("public_invites"):
            raise ConnectionManagerError("Public invitations are not enabled")
        else:  # request from public did
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                my_info = await wallet.create_local_did(SOV, ED25519)

            async with self.profile.session() as session:
                connection = await ConnRecord.retrieve_by_invitation_msg_id(
                    session=session,
                    invitation_msg_id=request._thread.pthid,
                    their_role=ConnRecord.Role.REQUESTER.rfc160,
                )
            if not connection:
                if not self.profile.settings.get("requests_through_public_did"):
                    raise ConnectionManagerError(
                        "Unsolicited connection requests to public DID is not enabled"
                    )
                connection = ConnRecord()
            connection.invitation_key = connection_key
            connection.my_did = my_info.did
            connection.their_role = ConnRecord.Role.RESPONDER.rfc160
            connection.their_did = request.connection.did
            connection.their_label = request.label
            connection.accept = (
                ConnRecord.ACCEPT_AUTO
                if self.profile.settings.get("debug.auto_accept_requests")
                else ConnRecord.ACCEPT_MANUAL
            )
            connection.state = ConnRecord.State.REQUEST.rfc160
            connection.connection_protocol = CONN_PROTO
            async with self.profile.session() as session:
                await connection.save(
                    session, reason="Received connection request from public DID"
                )

        async with self.profile.session() as session:
            # Attach the connection request so it can be found and responded to
            await connection.attach_request(session, request)

        # Clean associated oob record if not needed anymore
        oob_processor = self.profile.inject(OobMessageProcessor)
        await oob_processor.clean_finished_oob_record(self.profile, request)

        return connection

    async def create_response(
        self,
        connection: ConnRecord,
        my_endpoint: Optional[str] = None,
        mediation_id: Optional[str] = None,
    ) -> ConnectionResponse:
        """Create a connection response for a received connection request.

        Args:
            connection: The `ConnRecord` with a pending connection request
            my_endpoint: The endpoint I can be reached at
            mediation_id: The record id for mediation that contains routing_keys and
            service endpoint
        Returns:
            A tuple of the updated `ConnRecord` new `ConnectionResponse` message

        """
        self.deprecation_warning()
        ConnRecord.log_state(
            "Creating connection response",
            {"connection_id": connection.connection_id},
            settings=self.profile.settings,
        )

        mediation_records = await self._route_manager.mediation_records_for_connection(
            self.profile, connection, mediation_id
        )

        if ConnRecord.State.get(connection.state) not in (
            ConnRecord.State.REQUEST,
            ConnRecord.State.RESPONSE,
        ):
            raise ConnectionManagerError(
                "Connection is not in the request or response state"
            )

        async with self.profile.session() as session:
            request = await connection.retrieve_request(session)

        if connection.my_did:
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                my_info = await wallet.get_local_did(connection.my_did)
        else:
            async with self.profile.session() as session:
                wallet = session.inject(BaseWallet)
                my_info = await wallet.create_local_did(SOV, ED25519)
            connection.my_did = my_info.did

        # Idempotent; if routing has already been set up, no action taken
        await self._route_manager.route_connection_as_inviter(
            self.profile, connection, mediation_records
        )

        # Create connection response message
        if my_endpoint:
            my_endpoints = [my_endpoint]
        else:
            my_endpoints = []
            default_endpoint = self.profile.settings.get("default_endpoint")
            if default_endpoint:
                my_endpoints.append(default_endpoint)
            my_endpoints.extend(self.profile.settings.get("additional_endpoints", []))

        did_doc = await self.create_did_document(
            my_info,
            my_endpoints,
            mediation_records=mediation_records,
        )

        response = ConnectionResponse(
            connection=ConnectionDetail(did=my_info.did, did_doc=did_doc)
        )

        # Assign thread information
        response.assign_thread_from(request)
        response.assign_trace_from(request)
        # Sign connection field using the invitation key
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            await response.sign_field("connection", connection.invitation_key, wallet)

            # Update connection state
            connection.state = ConnRecord.State.RESPONSE.rfc160

            await connection.save(
                session,
                reason="Created connection response",
                log_params={"response": response},
            )

        # TODO It's possible the mediation request sent here might arrive
        # before the connection response. This would result in an error condition
        # difficult to accommodate for without modifying handlers for trust ping
        # to ensure the connection is active.
        async with self.profile.session() as session:
            send_mediation_request = await connection.metadata_get(
                session, MediationManager.SEND_REQ_AFTER_CONNECTION
            )
        if send_mediation_request:
            mgr = MediationManager(self.profile)
            _record, request = await mgr.prepare_request(connection.connection_id)
            responder = self.profile.inject(BaseResponder)
            await responder.send(request, connection_id=connection.connection_id)

        return response

    async def accept_response(
        self, response: ConnectionResponse, receipt: MessageReceipt
    ) -> ConnRecord:
        """Accept a connection response.

        Process a ConnectionResponse message by looking up
        the connection request and setting up the pairwise connection.

        Args:
            response: The `ConnectionResponse` to accept
            receipt: The message receipt

        Returns:
            The updated `ConnRecord` representing the connection

        Raises:
            ConnectionManagerError: If there is no DID associated with the
                connection response
            ConnectionManagerError: If the corresponding connection is not
                at the request or response stage

        """
        self.deprecation_warning()
        connection = None
        if response._thread:
            # identify the request by the thread ID
            try:
                async with self.profile.session() as session:
                    connection = await ConnRecord.retrieve_by_request_id(
                        session, response._thread_id
                    )
            except StorageNotFoundError:
                pass

        if not connection and receipt.sender_did:
            # identify connection by the DID they used for us
            try:
                async with self.profile.session() as session:
                    connection = await ConnRecord.retrieve_by_did(
                        session, receipt.sender_did, receipt.recipient_did
                    )
            except StorageNotFoundError:
                pass

        if not connection:
            raise ConnectionManagerError(
                "No corresponding connection request found",
                error_code=ProblemReportReason.RESPONSE_NOT_ACCEPTED.value,
            )

        if ConnRecord.State.get(connection.state) not in (
            ConnRecord.State.REQUEST,
            ConnRecord.State.RESPONSE,
        ):
            raise ConnectionManagerError(
                f"Cannot accept connection response for connection"
                f" in state: {connection.state}"
            )

        their_did = response.connection.did
        conn_did_doc = response.connection.did_doc
        if not conn_did_doc:
            raise ConnectionManagerError(
                "No DIDDoc provided; cannot connect to public DID"
            )
        if their_did != conn_did_doc.did:
            raise ConnectionManagerError("Connection DID does not match DIDDoc id")
        # Verify connection response using connection field
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            try:
                await response.verify_signed_field(
                    "connection", wallet, connection.invitation_key
                )
            except ValueError:
                raise ConnectionManagerError(
                    "connection field verification using invitation_key failed"
                )
        await self.store_did_document(conn_did_doc)

        connection.their_did = their_did
        connection.state = ConnRecord.State.RESPONSE.rfc160
        async with self.profile.session() as session:
            await connection.save(session, reason="Accepted connection response")

            send_mediation_request = await connection.metadata_get(
                session, MediationManager.SEND_REQ_AFTER_CONNECTION
            )
        if send_mediation_request:
            mgr = MediationManager(self.profile)
            _record, request = await mgr.prepare_request(connection.connection_id)
            responder = self.profile.inject(BaseResponder)
            await responder.send(request, connection_id=connection.connection_id)

        return connection

    async def receive_problem_report(
        self,
        conn_rec: ConnRecord,
        report: ConnectionProblemReport,
    ):
        """Receive problem report."""
        self.deprecation_warning()
        if not report.description:
            raise ConnectionManagerError("Missing description in problem report")

        if report.description.get("code") in {
            reason.value for reason in ProblemReportReason
        }:
            self._logger.info("Problem report indicates connection is abandoned")
            async with self.profile.session() as session:
                await conn_rec.abandon(
                    session,
                    reason=report.description.get("en"),
                )
        else:
            raise ConnectionManagerError(
                f"Received unrecognized problem report: {report.description}"
            )

    def manager_error_to_problem_report(
        self,
        e: ConnectionManagerError,
        message: Union[ConnectionRequest, ConnectionResponse],
        message_receipt,
    ) -> tuple[ConnectionProblemReport, Sequence[ConnectionTarget]]:
        """Convert ConnectionManagerError to problem report."""
        self._logger.exception("Error receiving connection request")
        targets = None
        report = None
        if e.error_code:
            report = ConnectionProblemReport(
                description={"en": e.message, "code": e.error_code}
            )
            report.assign_thread_from(message)
            if message.connection and message.connection.did_doc:
                try:
                    targets = self.diddoc_connection_targets(
                        message.connection.did_doc,
                        message_receipt.recipient_verkey,
                    )
                except ConnectionManagerError:
                    self._logger.exception("Error parsing DIDDoc for problem report")

        return report, targets
