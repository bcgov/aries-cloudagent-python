"""Classes to manage connections."""

from aries_cloudagent.connections.models.diddoc.diddoc import DIDDoc
import logging

from typing import Coroutine, Sequence, Tuple

from aries_cloudagent.protocols.coordinate_mediation.v1_0.manager import (
    MediationManager,
)

from ....cache.base import BaseCache
from ....config.base import InjectionError
from ....connections.base_manager import BaseConnectionManager
from ....connections.models.conn_record import ConnRecord
from ....connections.models.connection_target import ConnectionTarget
from ....connections.util import mediation_record_if_id
from ....core.error import BaseError
from ....core.profile import ProfileSession
from ....messaging.responder import BaseResponder
from ....protocols.routing.v1_0.manager import RoutingManager
from ....storage.error import StorageError, StorageNotFoundError
from ....transport.inbound.receipt import MessageReceipt
from ....wallet.base import BaseWallet, DIDInfo
from ....wallet.crypto import create_keypair, seed_to_did
from ....wallet.error import WalletNotFoundError
from ....wallet.util import bytes_to_b58
from ....multitenant.manager import MultitenantManager

from ...coordinate_mediation.v1_0.models.mediation_record import MediationRecord

from .messages.connection_invitation import ConnectionInvitation
from .messages.connection_request import ConnectionRequest
from .messages.connection_response import ConnectionResponse
from .messages.problem_report import ProblemReportReason
from .models.connection_detail import ConnectionDetail

LOGGER = logging.getLogger(__name__)


class ConnectionManagerError(BaseError):
    """Connection error."""


class ConnectionManager(BaseConnectionManager):
    """Class for managing connections."""

    def __init__(self, session: ProfileSession):
        """
        Initialize a ConnectionManager.

        Args:
            session: The profile session for this connection manager
        """
        self._session = session
        super().__init__(self._session)

    @property
    def session(self) -> ProfileSession:
        """
        Accessor for the current profile session.

        Returns:
            The profile session for this connection manager

        """
        return self._session

    async def create_invitation(
        self,
        my_label: str = None,
        my_endpoint: str = None,
        auto_accept: bool = None,
        public: bool = False,
        multi_use: bool = False,
        alias: str = None,
        routing_keys: Sequence[str] = None,
        recipient_keys: Sequence[str] = None,
        metadata: dict = None,
        mediation_id: str = None,
    ) -> Tuple[ConnRecord, ConnectionInvitation]:
        """
        Generate new connection invitation.

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

        Returns:
            A tuple of the new `ConnRecord` and `ConnectionInvitation` instances

        """
        # Mediation Record can still be None after this operation if no
        # mediation id passed and no default
        mediation_record = await mediation_record_if_id(
            self._session,
            mediation_id,
            or_default=True,
        )
        keylist_updates = None
        image_url = self._session.context.settings.get("image_url")

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")

        if not my_label:
            my_label = self._session.settings.get("default_label")
        wallet = self._session.inject(BaseWallet)
        if public:
            if not self._session.settings.get("public_invites"):
                raise ConnectionManagerError("Public invitations are not enabled")

            public_did = await wallet.get_public_did()
            if not public_did:
                raise ConnectionManagerError(
                    "Cannot create public invitation with no public DID"
                )

            if multi_use:
                raise ConnectionManagerError(
                    "Cannot use public and multi_use at the same time"
                )

            if metadata:
                raise ConnectionManagerError(
                    "Cannot use public and set metadata at the same time"
                )

            # FIXME - allow ledger instance to format public DID with prefix?
            invitation = ConnectionInvitation(
                label=my_label, did=f"did:sov:{public_did.did}", image_url=image_url
            )

            # Add mapping for multitenant relaying.
            # Mediation of public keys is not supported yet
            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(
                    wallet_id, public_did.verkey, skip_if_exists=True
                )

            return None, invitation

        invitation_mode = ConnRecord.INVITATION_MODE_ONCE
        if multi_use:
            invitation_mode = ConnRecord.INVITATION_MODE_MULTI

        if recipient_keys:
            # TODO: register recipient keys for relay
            # TODO: check that recipient keys are in wallet
            invitation_key = recipient_keys[0]  # TODO first key appropriate?
        else:
            # Create and store new invitation key
            invitation_signing_key = await wallet.create_signing_key()
            invitation_key = invitation_signing_key.verkey
            recipient_keys = [invitation_key]
            mediation_mgr = MediationManager(self._session.profile)
            keylist_updates = await mediation_mgr.add_key(
                invitation_key, keylist_updates
            )

            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(wallet_id, invitation_key)

        accept = (
            ConnRecord.ACCEPT_AUTO
            if (
                auto_accept
                or (
                    auto_accept is None
                    and self._session.settings.get("debug.auto_accept_requests")
                )
            )
            else ConnRecord.ACCEPT_MANUAL
        )

        # Create connection record
        connection = ConnRecord(
            invitation_key=invitation_key,  # TODO: determine correct key to use
            their_role=ConnRecord.Role.REQUESTER.rfc160,
            state=ConnRecord.State.INVITATION.rfc160,
            accept=accept,
            invitation_mode=invitation_mode,
            alias=alias,
        )

        await connection.save(self._session, reason="Created new invitation")

        routing_keys = []
        my_endpoint = my_endpoint or self._session.settings.get("default_endpoint")

        # The base wallet can act as a mediator for all tenants
        if multitenant_mgr and wallet_id:
            base_mediation_record = await multitenant_mgr.get_default_mediator()

            if base_mediation_record:
                routing_keys = base_mediation_record.routing_keys
                my_endpoint = base_mediation_record.endpoint

                # If we use a mediator for the base wallet we don't
                # need to register the key at the subwallet mediator
                # because it only needs to know the key of the base mediator
                # sub wallet mediator -> base wallet mediator -> agent
                keylist_updates = None
        if mediation_record:
            routing_keys = [*routing_keys, *mediation_record.routing_keys]
            my_endpoint = mediation_record.endpoint

            # Save that this invitation was created with mediation
            await connection.metadata_set(
                self._session, "mediation", {"id": mediation_id}
            )

            if keylist_updates:
                responder = self._session.inject(BaseResponder, required=False)
                await responder.send(
                    keylist_updates, connection_id=mediation_record.connection_id
                )

        # Create connection invitation message
        # Note: Need to split this into two stages to support inbound routing of invites
        # Would want to reuse create_did_document and convert the result
        invitation = ConnectionInvitation(
            label=my_label,
            recipient_keys=recipient_keys,
            routing_keys=routing_keys,
            endpoint=my_endpoint,
            image_url=image_url,
        )
        await connection.attach_invitation(self._session, invitation)

        if metadata:
            for key, value in metadata.items():
                await connection.metadata_set(self._session, key, value)

        return connection, invitation

    async def receive_invitation(
        self,
        invitation: ConnectionInvitation,
        their_public_did: str = None,
        auto_accept: bool = None,
        alias: str = None,
        mediation_id: str = None,
        mediation_record: MediationRecord = None,
    ) -> ConnRecord:
        """
        Create a new connection record to track a received invitation.

        Args:
            invitation: The `ConnectionInvitation` to store
            auto_accept: set to auto-accept the invitation (None to use config)
            alias: optional alias to set on the record

        Returns:
            The new `ConnRecord` instance

        """
        if not invitation.did:
            if not invitation.recipient_keys:
                raise ConnectionManagerError("Invitation must contain recipient key(s)")
            if not invitation.endpoint:
                raise ConnectionManagerError("Invitation must contain an endpoint")
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
        connection = ConnRecord(
            invitation_key=invitation.recipient_keys and invitation.recipient_keys[0],
            their_label=invitation.label,
            their_role=ConnRecord.Role.RESPONDER.rfc160,
            state=ConnRecord.State.INVITATION.rfc160,
            accept=accept,
            alias=alias,
            their_public_did=their_public_did,
        )

        await connection.save(
            self._session,
            reason="Created new connection record from invitation",
            log_params={"invitation": invitation, "their_label": invitation.label},
        )

        # Save the invitation for later processing
        await connection.attach_invitation(self._session, invitation)

        if connection.accept == ConnRecord.ACCEPT_AUTO:
            request = await self.create_request(connection, mediation_id=mediation_id)
            responder = self._session.inject(BaseResponder, required=False)
            if responder:
                await responder.send(request, connection_id=connection.connection_id)
                # refetch connection for accurate state
                connection = await ConnRecord.retrieve_by_id(
                    self._session, connection.connection_id
                )
        else:
            LOGGER.debug("Connection invitation will await acceptance")
        return connection

    async def create_request(
        self,
        connection: ConnRecord,
        my_label: str = None,
        my_endpoint: str = None,
        mediation_id: str = None,
    ) -> ConnectionRequest:
        """
        Create a new connection request for a previously-received invitation.

        Args:
            connection: The `ConnRecord` representing the invitation to accept
            my_label: My label
            my_endpoint: My endpoint

        Returns:
            A new `ConnectionRequest` message to send to the other agent

        """

        keylist_updates = None

        # Mediation Record can still be None after this operation if no
        # mediation id passed and no default
        mediation_record = await mediation_record_if_id(
            self._session,
            mediation_id,
            or_default=True,
        )

        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")
        base_mediation_record = None

        if multitenant_mgr and wallet_id:
            base_mediation_record = await multitenant_mgr.get_default_mediator()

        my_info = None
        wallet = self._session.inject(BaseWallet)
        if connection.my_did:
            my_info = await wallet.get_local_did(connection.my_did)
        else:
            # Create new DID for connection
            my_info = await wallet.create_local_did(method_name="peer")
            connection.my_did = my_info.did
            mediation_mgr = MediationManager(self._session.profile)
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
            connection.inbound_connection_id,
            my_endpoints,
            mediation_records=list(
                filter(None, [base_mediation_record, mediation_record])
            ),
            svc_type=DIDDoc.SERVICE_TYPE_V0,
        )

        if not my_label:
            my_label = self._session.settings.get("default_label")
        request = ConnectionRequest(
            label=my_label,
            connection=ConnectionDetail(did=connection.my_did, did_doc=did_doc),
            image_url=self._session.settings.get("image_url"),
        )

        # Update connection state
        connection.request_id = request._id
        connection.state = ConnRecord.State.REQUEST.rfc160

        await connection.save(self._session, reason="Created connection request")

        # Notify mediator of keylist changes
        if keylist_updates and mediation_record:
            # send a update keylist message with new recipient keys.
            responder = self._session.inject(BaseResponder, required=False)
            await responder.send(
                keylist_updates, connection_id=mediation_record.connection_id
            )

        return request

    async def receive_request(
        self,
        request: ConnectionRequest,
        receipt: MessageReceipt,
        mediation_id: str = None,
    ) -> ConnRecord:
        """
        Receive and store a connection request.

        Args:
            request: The `ConnectionRequest` to accept
            receipt: The message receipt

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
        connection = None
        connection_key = None
        my_info = None

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")
        wallet = self._session.inject(BaseWallet)

        # Determine what key will need to sign the response
        if receipt.recipient_did_public:
            my_info = await wallet.get_local_did(receipt.recipient_did)
            connection_key = my_info.verkey
        else:
            connection_key = receipt.recipient_verkey
            try:
                connection = await ConnRecord.retrieve_by_invitation_key(
                    session=self._session,
                    invitation_key=connection_key,
                    their_role=ConnRecord.Role.REQUESTER.rfc160,
                )
            except StorageNotFoundError:
                raise ConnectionManagerError(
                    "No invitation found for pairwise connection "
                    f"in state {ConnRecord.State.INVITATION.rfc160}: "
                    "a prior connection request may have updated the connection state"
                )

        invitation = None
        if connection:
            invitation = await connection.retrieve_invitation(self._session)
            connection_key = connection.invitation_key
            ConnRecord.log_state(
                "Found invitation",
                {"invitation": invitation},
                settings=self._session.settings,
            )

            if connection.is_multiuse_invitation:
                wallet = self._session.inject(BaseWallet)
                my_info = await wallet.create_local_did(method_name="peer")
                keylist_updates = await mediation_mgr.add_key(
                    my_info.verkey, keylist_updates
                )

                new_connection = ConnRecord(
                    invitation_key=connection_key,
                    my_did=my_info.did,
                    state=ConnRecord.State.INVITATION.rfc160,
                    accept=connection.accept,
                    their_role=connection.their_role,
                )

                await new_connection.save(
                    self._session,
                    reason="Received connection request from multi-use invitation DID",
                )

                # Transfer metadata from multi-use to new connection
                # Must come after save so there's an ID to associate with metadata
                for key, value in (
                    await connection.metadata_get_all(self._session)
                ).items():
                    await new_connection.metadata_set(self._session, key, value)

                connection = new_connection

                # Add mapping for multitenant relay
                if multitenant_mgr and wallet_id:
                    await multitenant_mgr.add_key(wallet_id, my_info.verkey)
            else:
                # remove key from mediator keylist
                keylist_updates = await mediation_mgr.remove_key(
                    connection_key, keylist_updates
                )
        conn_did_doc = request.connection.did_doc
        if not conn_did_doc:
            raise ConnectionManagerError(
                "No DIDDoc provided; cannot connect to public DID"
            )
        if request.connection.did != conn_did_doc.did:
            raise ConnectionManagerError(
                "Connection DID does not match DIDDoc id",
                error_code=ProblemReportReason.REQUEST_NOT_ACCEPTED,
            )
        await self.store_did_document(conn_did_doc)

        if connection:
            connection.their_label = request.label
            connection.their_did = request.connection.did
            connection.state = ConnRecord.State.REQUEST.rfc160
            await connection.save(
                self._session, reason="Received connection request from invitation"
            )
        elif not self._session.settings.get("public_invites"):
            raise ConnectionManagerError("Public invitations are not enabled")
        else:  # request from public did
            my_info = await wallet.create_local_did(method_name="peer")
            # send update-keylist message with new recipient keys
            keylist_updates = await mediation_mgr.add_key(
                my_info.verkey, keylist_updates
            )

            # Add mapping for multitenant relay
            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(wallet_id, my_info.verkey)

            connection = ConnRecord(
                invitation_key=connection_key,
                my_did=my_info.did,
                their_role=ConnRecord.Role.RESPONDER.rfc160,
                their_did=request.connection.did,
                their_label=request.label,
                accept=(
                    ConnRecord.ACCEPT_AUTO
                    if self._session.settings.get("debug.auto_accept_requests")
                    else ConnRecord.ACCEPT_MANUAL
                ),
                state=ConnRecord.State.REQUEST.rfc160,
            )

            await connection.save(
                self._session, reason="Received connection request from public DID"
            )

        # Attach the connection request so it can be found and responded to
        await connection.attach_request(self._session, request)

        # Send keylist updates to mediator
        mediation_record = await mediation_record_if_id(self._session, mediation_id)
        if keylist_updates and mediation_record:
            responder = self._session.inject(BaseResponder, required=False)
            await responder.send(
                keylist_updates, connection_id=mediation_record.connection_id
            )

        if connection.accept == ConnRecord.ACCEPT_AUTO:
            response = await self.create_response(connection, mediation_id=mediation_id)
            responder = self._session.inject(BaseResponder, required=False)
            if responder:
                await responder.send_reply(
                    response, connection_id=connection.connection_id
                )
                # refetch connection for accurate state
                connection = await ConnRecord.retrieve_by_id(
                    self._session, connection.connection_id
                )
        else:
            LOGGER.debug("Connection request will await acceptance")

        return connection

    async def create_response(
        self,
        connection: ConnRecord,
        my_endpoint: str = None,
        mediation_id: str = None,
    ) -> ConnectionResponse:
        """
        Create a connection response for a received connection request.

        Args:
            connection: The `ConnRecord` with a pending connection request
            my_endpoint: The endpoint I can be reached at
            mediation_id: The record id for mediation that contains routing_keys and
            service endpoint
        Returns:
            A tuple of the updated `ConnRecord` new `ConnectionResponse` message

        """
        ConnRecord.log_state(
            "Creating connection response",
            {"connection_id": connection.connection_id},
            settings=self._session.settings,
        )

        keylist_updates = None
        mediation_record = await mediation_record_if_id(self._session, mediation_id)

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")
        base_mediation_record = None

        if multitenant_mgr and wallet_id:
            base_mediation_record = await multitenant_mgr.get_default_mediator()

        if ConnRecord.State.get(connection.state) not in (
            ConnRecord.State.REQUEST,
            ConnRecord.State.RESPONSE,
        ):
            raise ConnectionManagerError(
                "Connection is not in the request or response state"
            )

        request = await connection.retrieve_request(self._session)
        wallet = self._session.inject(BaseWallet)
        if connection.my_did:
            my_info = await wallet.get_local_did(connection.my_did)
        else:
            my_info = await wallet.create_local_did(method_name="peer")
            connection.my_did = my_info.did
            mediation_mgr = MediationManager(self._session.profile)
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
            connection.inbound_connection_id,
            my_endpoints,
            mediation_records=list(
                filter(None, [base_mediation_record, mediation_record])
            ),
            svc_type=DIDDoc.SERVICE_TYPE_V0,
        )

        response = ConnectionResponse(
            connection=ConnectionDetail(did=my_info.did, did_doc=did_doc)
        )

        # Assign thread information
        response.assign_thread_from(request)
        response.assign_trace_from(request)
        # Sign connection field using the invitation key
        wallet = self._session.inject(BaseWallet)
        await response.sign_field("connection", connection.invitation_key, wallet)

        # Update connection state
        connection.state = ConnRecord.State.RESPONSE.rfc160

        await connection.save(
            self._session,
            reason="Created connection response",
            log_params={"response": response},
        )

        # Update mediator if necessary
        if keylist_updates and mediation_record:
            responder = self._session.inject(BaseResponder, required=False)
            await responder.send(
                keylist_updates, connection_id=mediation_record.connection_id
            )

        # TODO It's possible the mediation request sent here might arrive
        # before the connection response. This would result in an error condition
        # difficult to accomodate for without modifying handlers for trust ping
        # to ensure the connection is active.
        send_mediation_request = await connection.metadata_get(
            self._session, MediationManager.SEND_REQ_AFTER_CONNECTION
        )
        if send_mediation_request:
            mgr = MediationManager(self._session.profile)
            _record, request = await mgr.prepare_request(connection.connection_id)
            responder = self._session.inject(BaseResponder)
            await responder.send(request, connection_id=connection.connection_id)

        return response

    async def accept_response(
        self, response: ConnectionResponse, receipt: MessageReceipt
    ) -> ConnRecord:
        """
        Accept a connection response.

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

        connection = None
        if response._thread:
            # identify the request by the thread ID
            try:
                connection = await ConnRecord.retrieve_by_request_id(
                    self._session, response._thread_id
                )
            except StorageNotFoundError:
                pass

        if not connection and receipt.sender_did:
            # identify connection by the DID they used for us
            try:
                connection = await ConnRecord.retrieve_by_did(
                    self._session, receipt.sender_did, receipt.recipient_did
                )
            except StorageNotFoundError:
                pass

        if not connection:
            raise ConnectionManagerError(
                "No corresponding connection request found",
                error_code=ProblemReportReason.RESPONSE_NOT_ACCEPTED,
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
        await self.store_did_document(conn_did_doc)

        connection.their_did = their_did
        connection.state = ConnRecord.State.RESPONSE.rfc160

        await connection.save(self._session, reason="Accepted connection response")

        send_mediation_request = await connection.metadata_get(
            self._session, MediationManager.SEND_REQ_AFTER_CONNECTION
        )
        if send_mediation_request:
            mgr = MediationManager(self._session.profile)
            _record, request = await mgr.prepare_request(connection.connection_id)
            responder = self._session.inject(BaseResponder)
            await responder.send(request, connection_id=connection.connection_id)

        return connection

    async def get_endpoints(self, conn_id: str) -> Tuple[str, str]:
        """
        Get connection endpoints.

        Args:
            conn_id: connection identifier

        Returns:
            Their endpoint for this connection

        """
        connection = await ConnRecord.retrieve_by_id(self._session, conn_id)

        wallet = self._session.inject(BaseWallet)
        my_did_info = await wallet.get_local_did(connection.my_did)
        my_endpoint = my_did_info.metadata.get(
            "endpoint",
            self._session.settings.get("default_endpoint"),
        )

        conn_targets = await self.get_connection_targets(
            connection_id=connection.connection_id,
            connection=connection,
        )
        return (my_endpoint, conn_targets[0].endpoint)

    async def create_static_connection(
        self,
        my_did: str = None,
        my_seed: str = None,
        their_did: str = None,
        their_seed: str = None,
        their_verkey: str = None,
        their_endpoint: str = None,
        their_label: str = None,
        alias: str = None,
    ) -> Tuple[DIDInfo, DIDInfo, ConnRecord]:
        """
        Register a new static connection (for use by the test suite).

        Args:
            my_did: override the DID used in the connection
            my_seed: provide a seed used to generate our DID and keys
            their_did: provide the DID used by the other party
            their_seed: provide a seed used to generate their DID and keys
            their_verkey: provide the verkey used by the other party
            their_endpoint: their URL endpoint for routing messages
            alias: an alias for this connection record

        Returns:
            Tuple: my DIDInfo, their DIDInfo, new `ConnRecord` instance

        """
        wallet = self._session.inject(BaseWallet)

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")
        base_mediation_record = None

        # seed and DID optional
        my_info = await wallet.create_local_did(seed=my_seed, did=my_did)

        # must provide their DID and verkey if the seed is not known
        if (not their_did or not their_verkey) and not their_seed:
            raise ConnectionManagerError(
                "Either a verkey or seed must be provided for the other party"
            )
        if not their_did:
            their_did = seed_to_did(their_seed)
        if not their_verkey:
            their_verkey_bin, _ = create_keypair(their_seed.encode())
            their_verkey = bytes_to_b58(their_verkey_bin)
        their_info = DIDInfo(their_did, their_verkey, {})

        # Create connection record
        connection = ConnRecord(
            invitation_mode=ConnRecord.INVITATION_MODE_STATIC,
            my_did=my_info.did,
            their_did=their_info.did,
            their_label=their_label,
            state=ConnRecord.State.COMPLETED.rfc160,
            alias=alias,
        )
        await connection.save(self._session, reason="Created new static connection")

        # Add mapping for multitenant relaying / mediation
        if multitenant_mgr and wallet_id:
            base_mediation_record = await multitenant_mgr.get_default_mediator()
            await multitenant_mgr.add_key(wallet_id, my_info.verkey)

        # Synthesize their DID doc
        did_doc = await self.create_did_document(
            their_info,
            None,
            [their_endpoint],
            mediation_records=[base_mediation_record]
            if base_mediation_record
            else None,
            svc_type=DIDDoc.SERVICE_TYPE_V0,
        )
        await self.store_did_document(did_doc)

        return my_info, their_info, connection

    async def find_connection(
        self,
        their_did: str,
        my_did: str = None,
        my_verkey: str = None,
        auto_complete=False,
    ) -> ConnRecord:
        """
        Look up existing connection information for a sender verkey.

        Args:
            their_did: Their DID
            my_did: My DID
            my_verkey: My verkey
            auto_complete: Should this connection automatically be promoted to active

        Returns:
            The located `ConnRecord`, if any

        """
        # self._log_state(
        #    "Finding connection",
        #    {"their_did": their_did, "my_did": my_did, "my_verkey": my_verkey},
        # )
        connection = None
        if their_did:
            try:
                connection = await ConnRecord.retrieve_by_did(
                    self._session, their_did, my_did
                )
            except StorageNotFoundError:
                pass

        if (
            connection
            and ConnRecord.State.get(connection.state) is ConnRecord.State.RESPONSE
            and auto_complete
        ):
            connection.state = ConnRecord.State.COMPLETED.rfc160
            await connection.save(self._session, reason="Connection promoted to active")

        if not connection and my_verkey:
            try:
                connection = await ConnRecord.retrieve_by_invitation_key(
                    self._session,
                    my_verkey,
                    their_role=ConnRecord.Role.REQUESTER.rfc160,
                )
            except StorageError:
                pass

        return connection

    async def find_inbound_connection(self, receipt: MessageReceipt) -> ConnRecord:
        """
        Deserialize an incoming message and further populate the request context.

        Args:
            receipt: The message receipt

        Returns:
            The `ConnRecord` associated with the expanded message, if any

        """

        cache_key = None
        connection = None
        resolved = False

        if receipt.sender_verkey and receipt.recipient_verkey:
            cache_key = (
                f"connection_by_verkey::{receipt.sender_verkey}"
                f"::{receipt.recipient_verkey}"
            )
            cache = self._session.inject(BaseCache, required=False)
            if cache:
                async with cache.acquire(cache_key) as entry:
                    if entry.result:
                        cached = entry.result
                        receipt.sender_did = cached["sender_did"]
                        receipt.recipient_did_public = cached["recipient_did_public"]
                        receipt.recipient_did = cached["recipient_did"]
                        connection = await ConnRecord.retrieve_by_id(
                            self._session, cached["id"]
                        )
                    else:
                        connection = await self.resolve_inbound_connection(receipt)
                        if connection:
                            cache_val = {
                                "id": connection.connection_id,
                                "sender_did": receipt.sender_did,
                                "recipient_did": receipt.recipient_did,
                                "recipient_did_public": receipt.recipient_did_public,
                            }
                            await entry.set_result(cache_val, 3600)
                        resolved = True

        if not connection and not resolved:
            connection = await self.resolve_inbound_connection(receipt)
        return connection

    async def resolve_inbound_connection(self, receipt: MessageReceipt) -> ConnRecord:
        """
        Populate the receipt DID information and find the related `ConnRecord`.

        Args:
            receipt: The message receipt

        Returns:
            The `ConnRecord` associated with the expanded message, if any

        """

        if receipt.sender_verkey:
            try:
                receipt.sender_did = await self.find_did_for_key(receipt.sender_verkey)
            except StorageNotFoundError:
                LOGGER.warning(
                    "No corresponding DID found for sender verkey: %s",
                    receipt.sender_verkey,
                )

        if receipt.recipient_verkey:
            try:
                wallet = self._session.inject(BaseWallet)
                my_info = await wallet.get_local_did_for_verkey(
                    receipt.recipient_verkey
                )
                receipt.recipient_did = my_info.did
                if "public" in my_info.metadata and my_info.metadata["public"] is True:
                    receipt.recipient_did_public = True
            except InjectionError:
                LOGGER.warning(
                    "Cannot resolve recipient verkey, no wallet defined by "
                    "context: %s",
                    receipt.recipient_verkey,
                )
            except WalletNotFoundError:
                LOGGER.warning(
                    "No corresponding DID found for recipient verkey: %s",
                    receipt.recipient_verkey,
                )

        return await self.find_connection(
            receipt.sender_did, receipt.recipient_did, receipt.recipient_verkey, True
        )

    async def get_connection_targets(
        self, *, connection_id: str = None, connection: ConnRecord = None
    ):
        """Create a connection target from a `ConnRecord`.

        Args:
            connection_id: The connection ID to search for
            connection: The connection record itself, if already available
        """
        if not connection_id:
            connection_id = connection.connection_id
        cache = self._session.inject(BaseCache, required=False)
        cache_key = f"connection_target::{connection_id}"
        if cache:
            async with cache.acquire(cache_key) as entry:
                if entry.result:
                    targets = [
                        ConnectionTarget.deserialize(row) for row in entry.result
                    ]
                else:
                    if not connection:
                        connection = await ConnRecord.retrieve_by_id(
                            self._session, connection_id
                        )
                    targets = await self.fetch_connection_targets(connection)
                    await entry.set_result([row.serialize() for row in targets], 3600)
        else:
            targets = await self.fetch_connection_targets(connection)
        return targets

    async def establish_inbound(
        self,
        connection: ConnRecord,
        inbound_connection_id: str,
        outbound_handler: Coroutine,
    ) -> str:
        """Assign the inbound routing connection for a connection record.

        Returns: the current routing state (request or done)

        """

        # The connection must have a verkey, but in the case of a received
        # invitation we might not have created one yet
        wallet = self._session.inject(BaseWallet)
        if connection.my_did:
            my_info = await wallet.get_local_did(connection.my_did)
        else:
            # Create new DID for connection
            my_info = await wallet.create_local_did(method_name="peer")
            connection.my_did = my_info.did

        try:
            router = await ConnRecord.retrieve_by_id(
                self._session, inbound_connection_id
            )
        except StorageNotFoundError:
            raise ConnectionManagerError(
                f"Routing connection not found: {inbound_connection_id}"
            )
        if not router.is_ready:
            raise ConnectionManagerError(
                f"Routing connection is not ready: {inbound_connection_id}"
            )
        connection.inbound_connection_id = inbound_connection_id

        route_mgr = RoutingManager(self._session.profile)

        await route_mgr.send_create_route(
            inbound_connection_id, my_info.verkey, outbound_handler
        )
        connection.routing_state = ConnRecord.ROUTING_STATE_REQUEST
        await connection.save(self._session)
        return connection.routing_state

    async def update_inbound(
        self, inbound_connection_id: str, recip_verkey: str, routing_state: str
    ):
        """Activate connections once a route has been established.

        Looks up pending connections associated with the inbound routing
        connection and marks the routing as complete.
        """
        conns = await ConnRecord.query(
            self._session, {"inbound_connection_id": inbound_connection_id}
        )
        wallet = self._session.inject(BaseWallet)

        for connection in conns:
            # check the recipient key
            if not connection.my_did:
                continue
            conn_info = await wallet.get_local_did(connection.my_did)
            if conn_info.verkey == recip_verkey:
                connection.routing_state = routing_state
                await connection.save(self._session)
