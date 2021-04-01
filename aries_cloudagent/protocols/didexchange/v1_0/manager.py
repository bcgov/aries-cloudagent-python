"""Classes to manage connection establishment under RFC 23 (DID exchange)."""

import json
import logging

from ....connections.models.conn_record import ConnRecord
from ....connections.models.diddoc import DIDDoc
from ....connections.base_manager import BaseConnectionManager
from ....connections.util import mediation_record_if_id
from ....core.error import BaseError
from ....core.profile import ProfileSession
from ....messaging.decorators.attach_decorator import AttachDecorator
from ....messaging.responder import BaseResponder
from ....storage.error import StorageNotFoundError
from ....transport.inbound.receipt import MessageReceipt
from ....wallet.base import BaseWallet
from ....wallet.did_posture import DIDPosture
from ....wallet.util import did_key_to_naked
from ....multitenant.manager import MultitenantManager

from ...coordinate_mediation.v1_0.manager import MediationManager
from ...out_of_band.v1_0.messages.invitation import (
    InvitationMessage as OOBInvitationMessage,
)

from .messages.complete import DIDXComplete
from .messages.request import DIDXRequest
from .messages.response import DIDXResponse
from .messages.problem_report import ProblemReportReason

LOGGER = logging.getLogger(__name__)


class DIDXManagerError(BaseError):
    """Connection error."""


class DIDXManager(BaseConnectionManager):
    """Class for managing connections under RFC 23 (DID exchange)."""

    def __init__(self, session: ProfileSession):
        """
        Initialize a DIDXManager.

        Args:
            session: The profile session for this did exchange manager
        """
        self._session = session
        super().__init__(self._session)

    @property
    def session(self) -> ProfileSession:
        """
        Accessor for the current profile session.

        Returns:
            The profile session for this did exchange manager

        """
        return self._session

    async def receive_invitation(
        self,
        invitation: OOBInvitationMessage,
        their_public_did: str = None,
        auto_accept: bool = None,
        alias: str = None,
        mediation_id: str = None,
    ) -> ConnRecord:  # leave in didexchange as it uses a responder: not out-of-band
        """
        Create a new connection record to track a received invitation.

        Args:
            invitation: invitation to store
            their_public_did: their public DID
            auto_accept: set to auto-accept invitation (None to use config)
            alias: optional alias to set on record
            mediation_id: record id for mediation with routing_keys, service endpoint

        Returns:
            The new `ConnRecord` instance

        """
        if not invitation.service_dids:
            if invitation.service_blocks:
                if not all(
                    s.recipient_keys and s.service_endpoint
                    for s in invitation.service_blocks
                ):
                    raise DIDXManagerError(
                        "All service blocks in invitation with no service DIDs "
                        "must contain recipient key(s) and service endpoint(s)"
                    )
            else:
                raise DIDXManagerError(
                    "Invitation must contain service blocks or service DIDs"
                )

        accept = (
            ConnRecord.ACCEPT_AUTO
            if (
                auto_accept
                or (
                    auto_accept is None
                    and self._session.settings.get("debug.auto_accept_invites")
                )
            )
            else ConnRecord.ACCEPT_MANUAL
        )

        # Create connection record
        conn_rec = ConnRecord(
            invitation_key=(
                # invitation.service_blocks[0].recipient_keys[0]
                did_key_to_naked(invitation.service_blocks[0].recipient_keys[0])
                if invitation.service_blocks
                else None
            ),
            invitation_msg_id=invitation._id,
            their_label=invitation.label,
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            accept=accept,
            alias=alias,
            their_public_did=their_public_did,
        )

        await conn_rec.save(
            self._session,
            reason="Created new connection record from invitation",
            log_params={
                "invitation": invitation,
                "their_role": ConnRecord.Role.RESPONDER.rfc23,
            },
        )

        # Save the invitation for later processing
        await conn_rec.attach_invitation(self._session, invitation)

        if conn_rec.accept == ConnRecord.ACCEPT_AUTO:
            request = await self.create_request(conn_rec, mediation_id=mediation_id)
            responder = self._session.inject(BaseResponder, required=False)
            if responder:
                await responder.send_reply(
                    request,
                    connection_id=conn_rec.connection_id,
                )

                conn_rec.state = ConnRecord.State.REQUEST.rfc23
                await conn_rec.save(self._session, reason="Sent connection request")
        else:
            LOGGER.debug("Connection invitation will await acceptance")

        return conn_rec

    async def create_request_implicit(
        self,
        their_public_did: str,
        my_label: str = None,
        my_endpoint: str = None,
        mediation_id: str = None,
    ) -> DIDXRequest:
        """
        Create a request against a public DID only (no explicit invitation).

        Args:
            their_public_did: public DID to which to request a connection
            my_label: my label for request
            my_endpoint: my endpoint
            mediation_id: record id for mediation with routing_keys, service endpoint

        Returns:
            DID exchange request

        """

        conn_rec = ConnRecord(
            my_did=None,  # create-request will fill in on local DID creation
            their_did=their_public_did,
            their_label=None,
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            invitation_key=None,
            invitation_msg_id=None,
            state=ConnRecord.State.REQUEST.rfc23,
            accept=None,
            alias=my_label,
            their_public_did=their_public_did,
        )
        return await self.create_request(  # saves and updates conn_rec
            conn_rec=conn_rec,
            my_label=my_label,
            my_endpoint=my_endpoint,
            mediation_id=mediation_id,
        )

    async def create_request(
        self,
        conn_rec: ConnRecord,
        my_label: str = None,
        my_endpoint: str = None,
        mediation_id: str = None,
    ) -> DIDXRequest:
        """
        Create a new connection request for a previously-received invitation.

        Args:
            conn_rec: The `ConnRecord` representing the invitation to accept
            my_label: My label for request
            my_endpoint: My endpoint
            mediation_id: The record id for mediation that contains routing_keys and
                service endpoint

        Returns:
            A new `DIDXRequest` message to send to the other agent

        """
        # Mediation Support
        mediation_mgr = MediationManager(self._session.profile)
        keylist_updates = None
        mediation_record = await mediation_record_if_id(
            self._session,
            mediation_id,
            or_default=True,
        )
        base_mediation_record = None

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")
        if multitenant_mgr and wallet_id:
            base_mediation_record = await multitenant_mgr.get_default_mediator()
        wallet = self._session.inject(BaseWallet)

        if conn_rec.my_did:
            my_info = await wallet.get_local_did(conn_rec.my_did)
        else:
            # Create new DID for connection
            my_info = await wallet.create_local_did(method_name="peer")
            conn_rec.my_did = my_info.did
            keylist_updates = await mediation_mgr.add_key(
                my_info.verkey, keylist_updates
            )
            # Add mapping for multitenant relay
            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(wallet_id, my_info.verkey)

        # Create connection request message
        if my_endpoint:
            my_endpoints = [my_endpoint]
        else:
            my_endpoints = []
            default_endpoint = self._session.settings.get("default_endpoint")
            if default_endpoint:
                my_endpoints.append(default_endpoint)
            my_endpoints.extend(self._session.settings.get("additional_endpoints", []))
        did_doc = await self.create_did_document(
            my_info,
            conn_rec.inbound_connection_id,
            my_endpoints,
            mediation_records=list(
                filter(None, [base_mediation_record, mediation_record])
            ),
        )
        pthid = conn_rec.invitation_msg_id or f"did:sov:{conn_rec.their_public_did}"
        LOGGER.error(did_doc.serialize(version=1))
        attach = AttachDecorator.data_base64(did_doc.serialize(version=1))
        await attach.data.sign(my_info.verkey, wallet)
        if not my_label:
            my_label = self._session.settings.get("default_label")
        request = DIDXRequest(
            label=my_label,
            did=conn_rec.my_did,
            did_doc_attach=attach,
        )
        request.assign_thread_id(thid=request._id, pthid=pthid)

        # Update connection state
        conn_rec.request_id = request._id
        conn_rec.state = ConnRecord.State.REQUEST.rfc23
        await conn_rec.save(self._session, reason="Created connection request")

        # Notify Mediator
        if keylist_updates and mediation_record:
            responder = self._session.inject(BaseResponder, required=False)
            await responder.send(
                keylist_updates, connection_id=mediation_record.connection_id
            )
        return request

    async def receive_request(
        self,
        request: DIDXRequest,
        recipient_did: str,
        recipient_verkey: str = None,
        my_endpoint: str = None,
        alias: str = None,
        auto_accept_implicit: bool = None,
        mediation_id: str = None,
    ) -> ConnRecord:
        """
        Receive and store a connection request.

        Args:
            request: The `DIDXRequest` to accept
            recipient_did: The (unqualified) recipient DID
            recipient_verkey: The recipient verkey: None for public recipient DID
            my_endpoint: My endpoint
            alias: Alias for the connection
            auto_accept: Auto-accept request against implicit invitation
            mediation_id: The record id for mediation that contains routing_keys and
                service endpoint
        Returns:
            The new or updated `ConnRecord` instance

        """
        ConnRecord.log_state(
            "Receiving connection request",
            {"request": request},
            settings=self._session.settings,
        )

        mediation_mgr = MediationManager(self._session.profile)
        keylist_updates = None
        conn_rec = None
        connection_key = None
        my_info = None
        wallet = self._session.inject(BaseWallet)

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")

        # Determine what key will need to sign the response
        if recipient_verkey:  # peer DID
            connection_key = recipient_verkey
        else:
            if not self._session.settings.get("public_invites"):
                raise DIDXManagerError(
                    "Public invitations are not enabled: connection request refused"
                )
            my_info = await wallet.get_local_did(recipient_did)
            if DIDPosture.get(my_info.metadata) not in (
                DIDPosture.PUBLIC,
                DIDPosture.POSTED,
            ):
                raise DIDXManagerError(f"Request DID {recipient_did} is not public")
            connection_key = my_info.verkey

        try:
            conn_rec = await ConnRecord.retrieve_by_invitation_key(
                session=self._session,
                invitation_key=connection_key,
                their_role=ConnRecord.Role.REQUESTER.rfc23,
            )
        except StorageNotFoundError:
            if recipient_verkey:
                raise DIDXManagerError(
                    "No explicit invitation found for pairwise connection "
                    f"in state {ConnRecord.State.INVITATION.rfc23}: "
                    "a prior connection request may have updated the connection state"
                )

        if conn_rec:  # invitation was explicit
            connection_key = conn_rec.invitation_key
            if conn_rec.is_multiuse_invitation:
                wallet = self._session.inject(BaseWallet)
                my_info = await wallet.create_local_did(method_name="peer")
                keylist_updates = await mediation_mgr.add_key(
                    my_info.verkey, keylist_updates
                )

                new_conn_rec = ConnRecord(
                    invitation_key=connection_key,
                    my_did=my_info.did,
                    state=ConnRecord.State.REQUEST.rfc23,
                    accept=conn_rec.accept,
                    their_role=conn_rec.their_role,
                )

                await new_conn_rec.save(
                    self._session,
                    reason="Received connection request from multi-use invitation DID",
                )

                # Transfer metadata from multi-use to new connection
                # Must come after save so there's an ID to associate with metadata
                for key, value in (
                    await conn_rec.metadata_get_all(self._session)
                ).items():
                    await new_conn_rec.metadata_set(self._session, key, value)

                conn_rec = new_conn_rec

                # Add mapping for multitenant relay
                if multitenant_mgr and wallet_id:
                    await multitenant_mgr.add_key(wallet_id, my_info.verkey)
            else:
                keylist_updates = await mediation_mgr.remove_key(
                    connection_key, keylist_updates
                )

        # request DID doc describes requester DID
        if not (request.did_doc_attach and request.did_doc_attach.data):
            raise DIDXManagerError(
                "DID Doc attachment missing or has no data: "
                "cannot connect to public DID"
            )
        if not await request.did_doc_attach.data.verify(wallet):
            raise DIDXManagerError("DID Doc signature failed verification")
        conn_did_doc = DIDDoc.from_json(request.did_doc_attach.data.signed.decode())
        if request.did != conn_did_doc.did:
            raise DIDXManagerError(
                (
                    f"Connection DID {request.did} does not match "
                    f"DID Doc id {conn_did_doc.did}"
                ),
                error_code=ProblemReportReason.REQUEST_NOT_ACCEPTED,
            )
        await self.store_did_document(conn_did_doc)

        if conn_rec:  # request is against explicit invitation
            auto_accept = (
                conn_rec.accept == ConnRecord.ACCEPT_AUTO
            )  # null=manual; oob-manager calculated at conn rec creation

            conn_rec.their_label = request.label
            if alias:
                conn_rec.alias = alias
            conn_rec.their_did = request.did
            conn_rec.state = ConnRecord.State.REQUEST.rfc23
            conn_rec.request_id = request._id
            await conn_rec.save(
                self._session, reason="Received connection request from invitation"
            )
        else:
            # request is against implicit invitation on public DID
            my_info = await wallet.create_local_did(method_name="peer")

            keylist_updates = await mediation_mgr.add_key(
                my_info.verkey, keylist_updates
            )

            # Add mapping for multitenant relay
            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(wallet_id, my_info.verkey)

            auto_accept = bool(
                auto_accept_implicit
                or (
                    auto_accept_implicit is None
                    and self._session.settings.get("debug.auto_accept_requests", False)
                )
            )

            conn_rec = ConnRecord(
                my_did=my_info.did,
                accept=(
                    ConnRecord.ACCEPT_AUTO if auto_accept else ConnRecord.ACCEPT_MANUAL
                ),
                their_did=request.did,
                their_label=request.label,
                alias=alias,
                their_role=ConnRecord.Role.REQUESTER.rfc23,
                invitation_key=connection_key,
                invitation_msg_id=None,
                request_id=request._id,
                state=ConnRecord.State.REQUEST.rfc23,
            )
            await conn_rec.save(
                self._session, reason="Received connection request from public DID"
            )

        # Attach the connection request so it can be found and responded to
        await conn_rec.attach_request(self._session, request)

        # Send keylist updates to mediator
        mediation_record = await mediation_record_if_id(self._session, mediation_id)
        if keylist_updates and mediation_record:
            responder = self._session.inject(BaseResponder, required=False)
            await responder.send(
                keylist_updates, connection_id=mediation_record.connection_id
            )

        if auto_accept:
            response = await self.create_response(
                conn_rec,
                my_endpoint,
                mediation_id=mediation_id,
            )
            responder = self._session.inject(BaseResponder, required=False)
            if responder:
                await responder.send_reply(
                    response, connection_id=conn_rec.connection_id
                )
                conn_rec.state = ConnRecord.State.RESPONSE.rfc23
                await conn_rec.save(self._session, reason="Sent connection response")
        else:
            LOGGER.debug("DID exchange request will await acceptance")

        return conn_rec

    async def create_response(
        self,
        conn_rec: ConnRecord,
        my_endpoint: str = None,
        mediation_id: str = None,
    ) -> DIDXResponse:
        """
        Create a connection response for a received connection request.

        Args:
            conn_rec: The `ConnRecord` with a pending connection request
            my_endpoint: Current agent endpoint
            mediation_id: The record id for mediation that contains routing_keys and
                service endpoint

        Returns:
            New `DIDXResponse` message

        """
        ConnRecord.log_state(
            "Creating connection response",
            {"connection_id": conn_rec.connection_id},
            settings=self._session.settings,
        )

        mediation_mgr = MediationManager(self._session.profile)
        keylist_updates = None
        mediation_record = await mediation_record_if_id(self._session, mediation_id)
        base_mediation_record = None

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")
        if multitenant_mgr and wallet_id:
            base_mediation_record = await multitenant_mgr.get_default_mediator()

        if ConnRecord.State.get(conn_rec.state) is not ConnRecord.State.REQUEST:
            raise DIDXManagerError(
                f"Connection not in state {ConnRecord.State.REQUEST.rfc23}"
            )

        request = await conn_rec.retrieve_request(self._session)
        wallet = self._session.inject(BaseWallet)
        if conn_rec.my_did:
            my_info = await wallet.get_local_did(conn_rec.my_did)
        else:
            my_info = await wallet.create_local_did(method_name="peer")
            conn_rec.my_did = my_info.did
            keylist_updates = await mediation_mgr.add_key(
                my_info.verkey, keylist_updates
            )
            # Add mapping for multitenant relay
            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(wallet_id, my_info.verkey)

        # Create connection response message
        if my_endpoint:
            my_endpoints = [my_endpoint]
        else:
            my_endpoints = []
            default_endpoint = self._session.settings.get("default_endpoint")
            if default_endpoint:
                my_endpoints.append(default_endpoint)
            my_endpoints.extend(self._session.settings.get("additional_endpoints", []))
        did_doc = await self.create_did_document(
            my_info,
            conn_rec.inbound_connection_id,
            my_endpoints,
            mediation_records=list(
                filter(None, [base_mediation_record, mediation_record])
            ),
        )
        attach = AttachDecorator.data_base64(did_doc.serialize(version=1))
        await attach.data.sign(conn_rec.invitation_key, wallet)
        response = DIDXResponse(did=my_info.did, did_doc_attach=attach)
        # Assign thread information
        response.assign_thread_from(request)
        response.assign_trace_from(request)

        # Update connection state
        conn_rec.state = ConnRecord.State.RESPONSE.rfc23
        await conn_rec.save(
            self._session,
            reason="Created connection response",
            log_params={"response": response},
        )

        # Update Mediator if necessary
        if keylist_updates and mediation_record:
            responder = self._session.inject(BaseResponder, required=False)
            await responder.send(
                keylist_updates, connection_id=mediation_record.connection_id
            )

        send_mediation_request = await conn_rec.metadata_get(
            self._session, MediationManager.SEND_REQ_AFTER_CONNECTION
        )
        if send_mediation_request:
            temp_mediation_mgr = MediationManager(self._session.profile)
            _record, request = await temp_mediation_mgr.prepare_request(
                conn_rec.connection_id
            )
            responder = self._session.inject(BaseResponder)
            await responder.send(request, connection_id=conn_rec.connection_id)

        return response

    async def accept_response(
        self,
        response: DIDXResponse,
        receipt: MessageReceipt,
    ) -> ConnRecord:
        """
        Accept a connection response under RFC 23 (DID exchange).

        Process a `DIDXResponse` message by looking up
        the connection request and setting up the pairwise connection.

        Args:
            response: The `DIDXResponse` to accept
            receipt: The message receipt

        Returns:
            The updated `ConnRecord` representing the connection

        Raises:
            DIDXManagerError: If there is no DID associated with the
                connection response
            DIDXManagerError: If the corresponding connection is not
                in the request-sent state

        """
        wallet = self._session.inject(BaseWallet)

        conn_rec = None
        if response._thread:
            # identify the request by the thread ID
            try:
                conn_rec = await ConnRecord.retrieve_by_request_id(
                    self._session, response._thread_id
                )
            except StorageNotFoundError:
                pass

        if not conn_rec and receipt.sender_did:
            # identify connection by the DID they used for us
            try:
                conn_rec = await ConnRecord.retrieve_by_did(
                    session=self._session,
                    their_did=receipt.sender_did,
                    my_did=receipt.recipient_did,
                    their_role=ConnRecord.Role.RESPONDER.rfc23,
                )
            except StorageNotFoundError:
                pass

        if not conn_rec:
            raise DIDXManagerError(
                "No corresponding connection request found",
                error_code=ProblemReportReason.RESPONSE_NOT_ACCEPTED,
            )

        if ConnRecord.State.get(conn_rec.state) is not ConnRecord.State.REQUEST:
            raise DIDXManagerError(
                "Cannot accept connection response for connection"
                f" in state: {conn_rec.state}"
            )

        their_did = response.did
        if not response.did_doc_attach:
            raise DIDXManagerError("No DIDDoc attached; cannot connect to public DID")
        conn_did_doc = await self.verify_diddoc(wallet, response.did_doc_attach)
        if their_did != conn_did_doc.did:
            raise DIDXManagerError(
                f"Connection DID {their_did} "
                f"does not match DID doc id {conn_did_doc.did}"
            )
        await self.store_did_document(conn_did_doc)

        conn_rec.their_did = their_did
        conn_rec.state = ConnRecord.State.RESPONSE.rfc23
        await conn_rec.save(self._session, reason="Accepted connection response")

        send_mediation_request = await conn_rec.metadata_get(
            self._session, MediationManager.SEND_REQ_AFTER_CONNECTION
        )
        if send_mediation_request:
            temp_mediation_mgr = MediationManager(self._session.profile)
            _record, request = await temp_mediation_mgr.prepare_request(
                conn_rec.connection_id
            )
            responder = self._session.inject(BaseResponder)
            await responder.send(request, connection_id=conn_rec.connection_id)

        # create and send connection-complete message
        complete = DIDXComplete()
        complete.assign_thread_from(response)
        responder = self._session.inject(BaseResponder, required=False)
        if responder:
            await responder.send_reply(complete, connection_id=conn_rec.connection_id)

            conn_rec.state = ConnRecord.State.COMPLETED.rfc23
            await conn_rec.save(self._session, reason="Sent connection complete")

        return conn_rec

    async def accept_complete(
        self,
        complete: DIDXComplete,
        receipt: MessageReceipt,
    ) -> ConnRecord:
        """
        Accept a connection complete message under RFC 23 (DID exchange).

        Process a `DIDXComplete` message by looking up
        the connection record and marking the exchange complete.

        Args:
            complete: The `DIDXComplete` to accept
            receipt: The message receipt

        Returns:
            The updated `ConnRecord` representing the connection

        Raises:
            DIDXManagerError: If the corresponding connection does not exist
                or is not in the response-sent state

        """
        conn_rec = None

        # identify the request by the thread ID
        try:
            conn_rec = await ConnRecord.retrieve_by_request_id(
                self._session, complete._thread_id
            )
        except StorageNotFoundError:
            raise DIDXManagerError(
                "No corresponding connection request found",
                error_code=ProblemReportReason.COMPLETE_NOT_ACCEPTED,
            )

        conn_rec.state = ConnRecord.State.COMPLETED.rfc23
        await conn_rec.save(self._session, reason="Received connection complete")

        return conn_rec

    async def verify_diddoc(
        self,
        wallet: BaseWallet,
        attached: AttachDecorator,
    ) -> DIDDoc:
        """Verify DIDDoc attachment and return signed data."""
        signed_diddoc_bytes = attached.data.signed
        if not signed_diddoc_bytes:
            raise DIDXManagerError("DID doc attachment is not signed.")
        if not await attached.data.verify(wallet):
            raise DIDXManagerError("DID doc attachment signature failed verification")

        return DIDDoc.deserialize(json.loads(signed_diddoc_bytes.decode()))
