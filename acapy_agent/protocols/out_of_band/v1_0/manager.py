"""Classes to manage connections."""

import asyncio
import logging
import re
from typing import List, Mapping, NamedTuple, Optional, Sequence, Text, Union

from uuid_utils import uuid4

from ....connections.base_manager import BaseConnectionManager
from ....connections.models.conn_record import ConnRecord
from ....core.error import BaseError
from ....core.event_bus import EventBus
from ....core.oob_processor import OobMessageProcessor
from ....core.profile import Profile
from ....did.did_key import DIDKey
from ....messaging.decorators.attach_decorator import AttachDecorator
from ....messaging.decorators.service_decorator import ServiceDecorator
from ....messaging.responder import BaseResponder
from ....messaging.valid import IndyDID
from ....storage.error import StorageNotFoundError
from ....transport.inbound.receipt import MessageReceipt
from ....wallet.base import BaseWallet
from ....wallet.did_info import DIDInfo, INVITATION_REUSE_KEY
from ....wallet.did_method import PEER2, PEER4
from ....wallet.error import WalletNotFoundError
from ....wallet.key_type import ED25519
from ...coordinate_mediation.v1_0.models.mediation_record import MediationRecord
from ...coordinate_mediation.v1_0.route_manager import RouteManager
from ...didcomm_prefix import DIDCommPrefix
from ...didexchange.v1_0.manager import DIDXManager
from ...issue_credential.v2_0.models.cred_ex_record import V20CredExRecord
from ...present_proof.v2_0.models.pres_exchange import V20PresExRecord
from .message_types import DEFAULT_VERSION
from .messages.invitation import HSProto, InvitationMessage
from .messages.problem_report import OOBProblemReport
from .messages.reuse import HandshakeReuse
from .messages.reuse_accept import HandshakeReuseAccept
from .messages.service import Service
from .messages.service import Service as ServiceMessage
from .models.invitation import InvitationRecord
from .models.oob_record import OobRecord

LOGGER = logging.getLogger(__name__)
REUSE_WEBHOOK_TOPIC = "acapy::webhook::connection_reuse"
REUSE_ACCEPTED_WEBHOOK_TOPIC = "acapy::webhook::connection_reuse_accepted"


class OutOfBandManagerError(BaseError):
    """Out of band error."""


class OutOfBandManagerNotImplementedError(BaseError):
    """Out of band error for unimplemented functionality."""


class InvitationCreator:
    """Class for creating an out of band invitation."""

    class CreateResult(NamedTuple):
        """Result from creating an invitation."""

        invitation_url: str
        invitation: InvitationMessage
        our_recipient_key: str
        connection: Optional[ConnRecord]
        service: Optional[ServiceDecorator]

    def __init__(
        self,
        profile: Profile,
        route_manager: RouteManager,
        oob: "OutOfBandManager",
        my_label: Optional[str] = None,
        my_endpoint: Optional[str] = None,
        auto_accept: Optional[bool] = None,
        public: bool = False,
        use_did: Optional[str] = None,
        use_did_method: Optional[str] = None,
        hs_protos: Optional[Sequence[HSProto]] = None,
        multi_use: bool = False,
        create_unique_did: bool = False,
        alias: Optional[str] = None,
        attachments: Optional[Sequence[Mapping]] = None,
        metadata: Optional[dict] = None,
        mediation_id: Optional[str] = None,
        service_accept: Optional[Sequence[Text]] = None,
        protocol_version: Optional[Text] = None,
        goal_code: Optional[Text] = None,
        goal: Optional[Text] = None,
    ):
        """Initialize the invitation creator."""
        if not (hs_protos or attachments):
            raise OutOfBandManagerError(
                "Invitation must include handshake protocols, "
                "request attachments, or both"
            )

        if not hs_protos and metadata:
            raise OutOfBandManagerError(
                "Cannot store metadata without handshake protocols"
            )

        if attachments and multi_use:
            raise OutOfBandManagerError(
                "Cannot create multi use invitation with attachments"
            )

        if public and use_did:
            raise OutOfBandManagerError("use_did and public are mutually exclusive")

        if public and use_did_method:
            raise OutOfBandManagerError(
                "use_did_method and public are mutually exclusive"
            )

        if use_did and use_did_method:
            raise OutOfBandManagerError(
                "use_did and use_did_method are mutually exclusive"
            )

        if create_unique_did and not use_did_method:
            LOGGER.error(
                "create_unique_did: `%s`, use_did_method: `%s`",
                create_unique_did,
                use_did_method,
            )
            raise OutOfBandManagerError(
                "create_unique_did can only be used with use_did_method"
            )

        if use_did_method and use_did_method not in DIDXManager.SUPPORTED_USE_DID_METHODS:
            raise OutOfBandManagerError(f"Unsupported use_did_method: {use_did_method}")

        self.profile = profile
        self.route_manager = route_manager
        self.oob = oob

        self.msg_id = str(uuid4())
        self.attachments = attachments

        self.handshake_protocols = [
            DIDCommPrefix.qualify_current(hsp.name) for hsp in hs_protos or []
        ] or None

        if not my_endpoint:
            my_endpoint = self.profile.settings.get("default_endpoint")
            assert my_endpoint
        self.my_endpoint = my_endpoint

        self.version = protocol_version or DEFAULT_VERSION

        if not my_label:
            my_label = self.profile.settings.get("default_label")
            assert my_label
        self.my_label = my_label

        self.accept = service_accept if protocol_version != "1.0" else None
        self.invitation_mode = (
            ConnRecord.INVITATION_MODE_MULTI
            if multi_use
            else ConnRecord.INVITATION_MODE_ONCE
        )
        self.alias = alias

        auto_accept = bool(
            auto_accept
            or (
                auto_accept is None
                and self.profile.settings.get("debug.auto_accept_requests")
            )
        )
        self.auto_accept = (
            ConnRecord.ACCEPT_AUTO if auto_accept else ConnRecord.ACCEPT_MANUAL
        )
        self.goal = goal
        self.goal_code = goal_code
        self.public = public
        self.use_did = use_did
        self.use_did_method = use_did_method
        self.multi_use = multi_use
        self.create_unique_did = create_unique_did
        self.image_url = self.profile.context.settings.get("image_url")

        self.mediation_id = mediation_id
        self.metadata = metadata

    async def create_attachment(self, attachment: Mapping, pthid: str) -> AttachDecorator:
        """Create attachment for OOB invitation."""
        a_type = attachment.get("type")
        a_id = attachment.get("id")

        if not a_type or not a_id:
            raise OutOfBandManagerError("Attachment must include type and id")

        async with self.profile.session() as session:
            # TODO How do we enable using v1 offers?
            if a_type == "credential-offer":
                cred_ex_rec = await V20CredExRecord.retrieve_by_id(
                    session,
                    a_id,
                )
                message = cred_ex_rec.cred_offer
            # TODO How do we enable using v1 requests?
            elif a_type == "present-proof":
                pres_ex_rec = await V20PresExRecord.retrieve_by_id(
                    session,
                    a_id,
                )
                message = pres_ex_rec.pres_request
            else:
                raise OutOfBandManagerError(f"Unknown attachment type: {a_type}")

        message.assign_thread_id(pthid=pthid)
        return InvitationMessage.wrap_message(message.serialize())

    async def create_attachments(
        self,
        invitation_msg_id: str,
        attachments: Optional[Sequence[Mapping]] = None,
    ) -> List[AttachDecorator]:
        """Create attachments for OOB invitation."""
        return [
            await self.create_attachment(attachment, invitation_msg_id)
            for attachment in attachments or []
        ]

    async def create(self) -> InvitationRecord:
        """Create the invitation, returning the result as an InvitationRecord."""
        attachments = await self.create_attachments(self.msg_id, self.attachments)
        mediation_record = await self.oob._route_manager.mediation_record_if_id(
            self.profile, self.mediation_id, or_default=True
        )

        if self.public:
            result = await self.handle_public(attachments, mediation_record)
        elif self.use_did:
            result = await self.handle_use_did(attachments, mediation_record)
        elif self.use_did_method:
            result = await self.handle_use_did_method(attachments, mediation_record)
        else:
            result = await self.handle_legacy_invite_key(attachments, mediation_record)

        oob_record = OobRecord(
            role=OobRecord.ROLE_SENDER,
            state=OobRecord.STATE_AWAIT_RESPONSE,
            connection_id=(
                result.connection.connection_id if result.connection else None
            ),
            invi_msg_id=self.msg_id,
            invitation=result.invitation,
            our_recipient_key=result.our_recipient_key,
            our_service=result.service,
            multi_use=self.multi_use,
        )

        async with self.profile.session() as session:
            await oob_record.save(session, reason="Created new oob invitation")

        return InvitationRecord(
            oob_id=oob_record.oob_id,
            state=InvitationRecord.STATE_INITIAL,
            invi_msg_id=self.msg_id,
            invitation=result.invitation,
            invitation_url=result.invitation_url,
        )

    async def handle_handshake_protos(
        self,
        invitation_key: str,
        msg: InvitationMessage,
        mediation_record: Optional[MediationRecord],
    ) -> ConnRecord:
        """Handle handshake protocol options, creating a ConnRecord.

        When handshake protocols are included in the create request, that means
        we intend to create a connection for the invitation. When absent,
        no connection is created, representing a connectionless exchange.
        """
        assert self.handshake_protocols

        if len(self.handshake_protocols) == 1:
            connection_protocol = DIDCommPrefix.unqualify(self.handshake_protocols[0])
        else:
            # We don't know which protocol will be used until the request is received
            connection_protocol = None

        conn_rec = ConnRecord(
            invitation_key=invitation_key,
            invitation_msg_id=self.msg_id,
            invitation_mode=self.invitation_mode,
            their_role=ConnRecord.Role.REQUESTER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            accept=self.auto_accept,
            alias=self.alias,
            connection_protocol=connection_protocol,
        )

        async with self.profile.transaction() as session:
            await conn_rec.save(session, reason="Created new invitation")
            await conn_rec.attach_invitation(session, msg)

            if self.metadata:
                for key, value in self.metadata.items():
                    await conn_rec.metadata_set(session, key, value)

            await session.commit()

        await self.route_manager.route_invitation(
            self.profile, conn_rec, mediation_record
        )

        return conn_rec

    def did_key_to_key(self, did_key: str) -> str:
        """Convert a DID key to a key."""
        if did_key.startswith("did:key:"):
            return DIDKey.from_did(did_key).public_key_b58
        return did_key

    def did_keys_to_keys(self, did_keys: Sequence[str]) -> List[str]:
        """Convert DID keys to keys."""
        return [self.did_key_to_key(did_key) for did_key in did_keys]

    async def handle_did(
        self,
        did_info: DIDInfo,
        attachments: Sequence[AttachDecorator],
        mediation_record: Optional[MediationRecord],
    ) -> CreateResult:
        """Handle use_did invitation creation."""
        invi_msg = InvitationMessage(
            _id=self.msg_id,
            label=self.my_label,
            handshake_protocols=self.handshake_protocols,
            requests_attach=attachments or None,
            services=[did_info.did],
            accept=self.accept,
            version=self.version,
            image_url=self.image_url,
        )
        endpoint, recipient_keys, routing_keys = await self.oob.resolve_invitation(
            did_info.did
        )
        invi_url = invi_msg.to_url(endpoint)

        if self.handshake_protocols:
            conn_rec = await self.handle_handshake_protos(
                did_info.verkey, invi_msg, mediation_record
            )
            our_service = None
        else:
            conn_rec = None
            await self.route_manager.route_verkey(
                self.profile, did_info.verkey, mediation_record
            )
            our_service = ServiceDecorator(
                recipient_keys=self.did_keys_to_keys(recipient_keys),
                endpoint=self.my_endpoint,
                routing_keys=self.did_keys_to_keys(routing_keys),
            )

        return self.CreateResult(
            invitation_url=invi_url,
            invitation=invi_msg,
            our_recipient_key=did_info.verkey,
            connection=conn_rec,
            service=our_service,
        )

    async def handle_public(
        self,
        attachments: Sequence[AttachDecorator],
        mediation_record: Optional[MediationRecord] = None,
    ) -> CreateResult:
        """Handle public invitation creation."""
        assert self.public
        if not self.profile.settings.get("public_invites"):
            raise OutOfBandManagerError("Public invitations are not enabled")

        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            public_did = await wallet.get_public_did()

        if not public_did:
            raise OutOfBandManagerError(
                "Cannot create public invitation with no public DID"
            )

        if bool(IndyDID.PATTERN.match(public_did.did)):
            public_did = DIDInfo(
                did=f"did:sov:{public_did.did}",
                verkey=public_did.verkey,
                metadata=public_did.metadata,
                method=public_did.method,
                key_type=public_did.key_type,
            )

        return await self.handle_did(public_did, attachments, mediation_record)

    async def handle_use_did(
        self,
        attachments: Sequence[AttachDecorator],
        mediation_record: Optional[MediationRecord],
    ) -> CreateResult:
        """Handle use_did invitation creation."""
        assert self.use_did
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            try:
                did_info = await wallet.get_local_did(self.use_did)
            except WalletNotFoundError:
                raise OutOfBandManagerError(
                    f"Cannot find DID for invitation reuse: {self.use_did}"
                )
        return await self.handle_did(did_info, attachments, mediation_record)

    async def handle_use_did_method(
        self,
        attachments: Sequence[AttachDecorator],
        mediation_record: Optional[MediationRecord],
    ) -> CreateResult:
        """Create an invitation using a DID method, optionally reusing one."""
        assert self.use_did_method
        mediation_records = [mediation_record] if mediation_record else []

        if self.my_endpoint:
            my_endpoints = [self.my_endpoint]
        else:
            my_endpoints = []
            default_endpoint = self.profile.settings.get("default_endpoint")
            if default_endpoint:
                my_endpoints.append(default_endpoint)
            my_endpoints.extend(self.profile.settings.get("additional_endpoints", []))

        did_peer_4 = self.use_did_method == "did:peer:4"

        my_info = None
        if not self.create_unique_did:
            # check wallet to see if there is an existing "invitation" DID available
            did_method = PEER4 if did_peer_4 else PEER2
            my_info = await self.oob.fetch_invitation_reuse_did(did_method)
            if not my_info:
                LOGGER.warning("No invitation DID found, creating new DID")

        if not my_info:
            did_metadata = (
                {INVITATION_REUSE_KEY: "true"} if not self.create_unique_did else {}
            )
            if did_peer_4:
                my_info = await self.oob.create_did_peer_4(
                    my_endpoints, mediation_records, did_metadata
                )
            else:
                my_info = await self.oob.create_did_peer_2(
                    my_endpoints, mediation_records, did_metadata
                )

        return await self.handle_did(my_info, attachments, mediation_record)

    async def handle_legacy_invite_key(
        self,
        attachments: Sequence[AttachDecorator],
        mediation_record: Optional[MediationRecord],
    ) -> CreateResult:
        """Create an invitation using legacy bare public key and inline service."""
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            connection_key = await wallet.create_signing_key(ED25519)

        routing_keys, routing_endpoint = await self.route_manager.routing_info(
            self.profile, mediation_record
        )
        routing_keys = [
            (
                key
                if len(key.split(":")) == 3
                else DIDKey.from_public_key_b58(key, ED25519).key_id
            )
            for key in routing_keys or []
        ]
        recipient_keys = [
            DIDKey.from_public_key_b58(connection_key.verkey, ED25519).key_id
        ]

        my_endpoint = routing_endpoint or self.my_endpoint

        invi_msg = InvitationMessage(
            _id=self.msg_id,
            label=self.my_label,
            handshake_protocols=self.handshake_protocols,
            requests_attach=attachments,
            accept=self.accept,
            image_url=self.image_url,
            version=self.version,
            services=[
                ServiceMessage(
                    _id="#inline",
                    _type="did-communication",
                    recipient_keys=recipient_keys,
                    service_endpoint=my_endpoint,
                    routing_keys=routing_keys,
                )
            ],
            goal=self.goal,
            goal_code=self.goal_code,
        )

        if self.handshake_protocols:
            conn_rec = await self.handle_handshake_protos(
                connection_key.verkey, invi_msg, mediation_record
            )
            our_service = None
        else:
            await self.route_manager.route_verkey(
                self.profile, connection_key.verkey, mediation_record
            )
            conn_rec = None
            our_service = ServiceDecorator(
                recipient_keys=self.did_keys_to_keys(recipient_keys),
                endpoint=my_endpoint,
                routing_keys=self.did_keys_to_keys(routing_keys),
            )

        return self.CreateResult(
            invitation_url=invi_msg.to_url(),
            invitation=invi_msg,
            our_recipient_key=connection_key.verkey,
            connection=conn_rec,
            service=our_service,
        )


class OutOfBandManager(BaseConnectionManager):
    """Class for managing out of band messages."""

    def __init__(self, profile: Profile):
        """Initialize a OutOfBandManager.

        Args:
            profile: The profile for this out of band manager
        """
        self._profile = profile
        super().__init__(self._profile)

    @property
    def profile(self) -> Profile:
        """Accessor for the current profile.

        Returns:
            The profile for this connection manager

        """
        return self._profile

    async def create_invitation(
        self,
        my_label: Optional[str] = None,
        my_endpoint: Optional[str] = None,
        auto_accept: Optional[bool] = None,
        public: bool = False,
        use_did: Optional[str] = None,
        use_did_method: Optional[str] = None,
        hs_protos: Optional[Sequence[HSProto]] = None,
        multi_use: bool = False,
        create_unique_did: bool = False,
        alias: Optional[str] = None,
        attachments: Optional[Sequence[Mapping]] = None,
        metadata: Optional[dict] = None,
        mediation_id: Optional[str] = None,
        service_accept: Optional[Sequence[Text]] = None,
        protocol_version: Optional[Text] = None,
        goal_code: Optional[Text] = None,
        goal: Optional[Text] = None,
    ) -> InvitationRecord:
        """Generate new connection invitation.

        This method generates a new connection invitation, which represents an out-of-band
        communication channel. In the future and in practice, these sort of invitations
        will be received over any number of channels such as SMS, Email, QR Code, NFC,
        etc.

        Args:
            my_label (Optional[str]): Label for this connection.
            my_endpoint (Optional[str]): Endpoint where the other party can reach me.
            auto_accept (Optional[bool]): Auto-accept a corresponding connection request
                (None to use config).
            public (bool): Set to True to create an invitation from the public DID.
            use_did (Optional[str]): DID to use for the invitation.
            use_did_method (Optional[str]): DID method to use for the invitation.
            hs_protos (Optional[Sequence[HSProto]]): List of handshake protocols to
                include.
            multi_use (bool): Set to True to create an invitation for multiple-use
                connection.
            create_unique_did (bool): Set to True to create a unique DID for the
                invitation.
            alias (Optional[str]): Optional alias to apply to the connection for later
                use.
            attachments (Optional[Sequence[Mapping]]): List of attachments in the form of
                {"id": ..., "type": ...}.
            metadata (Optional[dict]): Additional metadata for the invitation.
            mediation_id (Optional[str]): Mediation ID for the invitation.
            service_accept (Optional[Sequence[Text]]): Optional list of mime types in the
                order of preference of the sender that the receiver can use in responding
                to the message.
            protocol_version (Optional[Text]): OOB protocol version [1.0, 1.1].
            goal_code (Optional[Text]): Optional self-attested code for receiver logic.
            goal (Optional[Text]): Optional self-attested string for receiver logic.

        Returns:
            InvitationRecord: The generated invitation record.

        """
        creator = InvitationCreator(
            self.profile,
            self._route_manager,
            self,
            my_label,
            my_endpoint,
            auto_accept,
            public,
            use_did,
            use_did_method,
            hs_protos,
            multi_use,
            create_unique_did,
            alias,
            attachments,
            metadata,
            mediation_id,
            service_accept,
            protocol_version,
            goal_code,
            goal,
        )
        return await creator.create()

    async def receive_invitation(
        self,
        invitation: InvitationMessage,
        use_existing_connection: bool = True,
        auto_accept: Optional[bool] = None,
        alias: Optional[str] = None,
        mediation_id: Optional[str] = None,
    ) -> OobRecord:
        """Receive an out of band invitation message.

        Args:
            invitation: invitation message
            use_existing_connection: whether to use existing connection if possible
            auto_accept: whether to accept the invitation automatically
            alias: Alias for connection record
            mediation_id: mediation identifier

        Returns:
            ConnRecord, serialized

        """
        if mediation_id:
            try:
                await self._route_manager.mediation_record_if_id(
                    self.profile, mediation_id
                )
            except StorageNotFoundError:
                mediation_id = None

        # There must be exactly 1 service entry
        if len(invitation.services) != 1:
            raise OutOfBandManagerError("service array must have exactly one element")

        if not (invitation.requests_attach or invitation.handshake_protocols):
            raise OutOfBandManagerError(
                "Invitation must specify handshake_protocols, requests_attach, or both"
            )

        # Get the single service item
        oob_service_item = invitation.services[0]

        # service_accept
        service_accept = invitation.accept

        # Get the DID public did, if any (might also be a did:peer)
        public_did = None
        if isinstance(oob_service_item, str):
            if bool(IndyDID.PATTERN.match(oob_service_item)):
                public_did = oob_service_item.split(":")[-1]
            else:
                public_did = oob_service_item

        conn_rec = None

        # Find existing connection - only if started by an invitation with Public DID
        # (or did:peer) and use_existing_connection is true
        if (
            public_did is not None and use_existing_connection
        ):  # invite has public DID: seek existing connection
            if public_did.startswith("did:peer:4"):
                search_public_did = self.long_did_peer_to_short(public_did)
            else:
                search_public_did = public_did

            LOGGER.debug(
                "Trying to find existing connection for oob invitation with "
                f"did {search_public_did}"
            )

            async with self._profile.session() as session:
                conn_rec = await ConnRecord.find_existing_connection(
                    session=session, their_public_did=search_public_did
                )

        oob_record = OobRecord(
            role=OobRecord.ROLE_RECEIVER,
            invi_msg_id=invitation._id,
            invitation=invitation,
            state=OobRecord.STATE_INITIAL,
            connection_id=conn_rec.connection_id if conn_rec else None,
        )

        # Try to reuse the connection. If not accepted sets the conn_rec to None
        if conn_rec and not invitation.requests_attach:
            oob_record = await self._handle_handshake_reuse(
                oob_record, conn_rec, invitation._version
            )

            LOGGER.warning(
                f"Connection reuse request finished with state {oob_record.state}"
            )

            if oob_record.state == OobRecord.STATE_ACCEPTED:
                return oob_record
            else:
                # Set connection record to None if not accepted
                # Will make new connection
                conn_rec = None

        # Try to create a connection. Either if the reuse failed or we didn't have a
        # connection yet. Throws an error if connection could not be created
        if not conn_rec and invitation.handshake_protocols:
            oob_record = await self._perform_handshake(
                oob_record=oob_record,
                alias=alias,
                auto_accept=auto_accept,
                mediation_id=mediation_id,
                service_accept=service_accept,
            )
            LOGGER.debug(
                f"Performed handshake with connection {oob_record.connection_id}"
            )
            # re-fetch connection record
            async with self.profile.session() as session:
                conn_rec = await ConnRecord.retrieve_by_id(
                    session, oob_record.connection_id
                )

        # If a connection record is associated with the oob record we can remove it now as
        # we can leverage the connection for all exchanges. Otherwise we need to keep it
        # around for the connectionless exchange
        if conn_rec:
            oob_record.state = OobRecord.STATE_DONE
            async with self.profile.session() as session:
                await oob_record.emit_event(session)
                await oob_record.delete_record(session)
        else:
            oob_record.state = OobRecord.STATE_PREPARE_RESPONSE
            async with self.profile.session() as session:
                await oob_record.save(session)

        # Handle any attachments
        if invitation.requests_attach:
            LOGGER.debug(
                f"Process attached messages for oob exchange {oob_record.oob_id} "
                f"(connection_id {oob_record.connection_id})"
            )

            # FIXME: this should ideally be handled using an event handler. Once the
            # connection is ready we start processing the attached messages.
            # For now we use the timeout method
            if (
                conn_rec
                and not conn_rec.is_ready
                and not await self._wait_for_conn_rec_active(conn_rec.connection_id)
            ):
                raise OutOfBandManagerError(
                    "Connection not ready to process attach message "
                    f"for connection_id: {oob_record.connection_id} and "
                    f"invitation_msg_id {invitation._id}",
                )

            if not conn_rec:
                # Create and store new key for connectionless exchange
                async with self.profile.session() as session:
                    wallet = session.inject(BaseWallet)
                    connection_key = await wallet.create_signing_key(ED25519)
                    oob_record.our_recipient_key = connection_key.verkey
                    oob_record.our_service = ServiceDecorator(
                        recipient_keys=[connection_key.verkey],
                        endpoint=self.profile.settings.get("default_endpoint"),
                        routing_keys=[],
                    ).serialize()

                    # Need to make sure the created key is routed by the base wallet
                    await self._route_manager.route_verkey(
                        self.profile, connection_key.verkey
                    )
                    await oob_record.save(session)

            await self._process_request_attach(oob_record)

        return oob_record

    async def _process_request_attach(self, oob_record: OobRecord):
        invitation = oob_record.invitation

        message_processor = self.profile.inject(OobMessageProcessor)
        messages = [attachment.content for attachment in invitation.requests_attach]

        their_service = None
        if not oob_record.connection_id:
            service = oob_record.invitation.services[0]
            their_service = await self._service_decorator_from_service(service)
            if their_service:
                LOGGER.debug("Found service for oob record %s", their_service)
            else:
                LOGGER.debug("No service decorator obtained from %s", service)

        await message_processor.handle_message(
            self.profile, messages, oob_record=oob_record, their_service=their_service
        )

    async def _service_decorator_from_service(
        self, service: Union[Service, str]
    ) -> Optional[ServiceDecorator]:
        if isinstance(service, str):
            (
                endpoint,
                recipient_keys,
                routing_keys,
            ) = await self.resolve_invitation(service)

            if not endpoint:
                return None

            return ServiceDecorator(
                endpoint=endpoint,
                recipient_keys=recipient_keys,
                routing_keys=routing_keys,
            )
        elif isinstance(service, Service):
            endpoint = service.service_endpoint

            if not endpoint:
                return None

            recipient_keys = [
                DIDKey.from_did(did_key).public_key_b58
                for did_key in service.recipient_keys
            ]
            routing_keys = [
                DIDKey.from_did(did_key).public_key_b58
                for did_key in service.routing_keys
            ]

            return ServiceDecorator(
                endpoint=endpoint,
                recipient_keys=recipient_keys,
                routing_keys=routing_keys,
            )
        else:
            LOGGER.warning(
                "Unexpected type `%s` passed to `_service_decorator_from_service`",
                type(service),
            )
            return None

    async def _wait_for_reuse_response(self, oob_id: str, timeout: int = 15) -> OobRecord:
        """Wait for reuse response.

        Wait for reuse response message state. Either by receiving a reuse accepted or
        problem report. If no answer is received within the timeout, the state will be
        set to reuse_not_accepted

        Args:
            oob_id: Identifier of the oob record
            timeout: The timeout in seconds to wait for the reuse state [default=15]

        Returns:
            OobRecord: The oob record associated with the provided id.

        """
        OOB_REUSE_RESPONSE_STATE = re.compile(
            "^acapy::record::out_of_band::(reuse-accepted|reuse-not-accepted)$"
        )

        async def _wait_for_state() -> OobRecord:
            event = self.profile.inject(EventBus)
            with event.wait_for_event(
                self.profile,
                OOB_REUSE_RESPONSE_STATE,
                lambda event: event.payload.get("oob_id") == oob_id,
            ) as await_event:
                # After starting the listener first retrieve the record from storage.
                # This rules out the scenario where the record was in the desired state
                # Before starting the event listener
                async with self.profile.session() as session:
                    oob_record = await OobRecord.retrieve_by_id(session, oob_id)

                    if oob_record.state in [
                        OobRecord.STATE_ACCEPTED,
                        OobRecord.STATE_NOT_ACCEPTED,
                    ]:
                        return oob_record

                LOGGER.debug(f"Wait for oob {oob_id} to receive reuse accepted message")
                event = await await_event
                LOGGER.debug("Received reuse response message")
                return OobRecord.deserialize(event.payload)

        try:
            oob_record = await asyncio.wait_for(
                _wait_for_state(),
                timeout,
            )

            return oob_record
        except asyncio.TimeoutError:
            async with self.profile.session() as session:
                oob_record = await OobRecord.retrieve_by_id(session, oob_id)
                return oob_record

    async def _wait_for_conn_rec_active(
        self, connection_id: str, timeout: int = 7
    ) -> Optional[ConnRecord]:
        CONNECTION_READY_EVENT = re.compile(
            "^acapy::record::connections::(active|completed|response)$"
        )

        LOGGER.debug(f"Wait for connection {connection_id} to become active")

        async def _wait_for_state() -> ConnRecord:
            event = self.profile.inject(EventBus)
            with event.wait_for_event(
                self.profile,
                CONNECTION_READY_EVENT,
                lambda event: event.payload.get("connection_id") == connection_id,
            ) as await_event:
                # After starting the listener first retrieve the record from storage.
                # This rules out the scenario where the record was in the desired state
                # Before starting the event listener
                async with self.profile.session() as session:
                    conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
                    if conn_record.is_ready:
                        return conn_record

                LOGGER.debug(f"Wait for connection {connection_id} to become active")
                # Wait for connection record to be in state
                event = await await_event
                return ConnRecord.deserialize(event.payload)

        try:
            return await asyncio.wait_for(
                _wait_for_state(),
                timeout,
            )

        except asyncio.TimeoutError:
            LOGGER.warning(f"Connection for connection_id {connection_id} not ready")
            return None

    async def _handle_handshake_reuse(
        self, oob_record: OobRecord, conn_record: ConnRecord, version: str
    ) -> OobRecord:
        # Send handshake reuse
        oob_record = await self._create_handshake_reuse_message(
            oob_record, conn_record, version
        )

        # Wait for the reuse accepted message
        oob_record = await self._wait_for_reuse_response(oob_record.oob_id)
        LOGGER.debug(
            f"Oob reuse for oob id {oob_record.oob_id} with connection "
            f"{oob_record.connection_id} finished with state {oob_record.state}"
        )

        if oob_record.state != OobRecord.STATE_ACCEPTED:
            # Remove associated connection id as reuse has ben denied
            oob_record.connection_id = None
            oob_record.state = OobRecord.STATE_NOT_ACCEPTED

            # OOB_TODO: replace webhook event with new oob webhook event
            # Emit webhook if the reuse was not accepted
            await self.profile.notify(
                REUSE_ACCEPTED_WEBHOOK_TOPIC,
                {
                    "thread_id": oob_record.reuse_msg_id,
                    "connection_id": conn_record.connection_id,
                    "state": "rejected",
                    "comment": (
                        "No HandshakeReuseAccept message received, "
                        f"connection {conn_record.connection_id} ",
                        f"and invitation {oob_record.invitation._id}",
                    ),
                },
            )

            async with self.profile.session() as session:
                await oob_record.save(session)

        return oob_record

    async def _perform_handshake(
        self,
        *,
        oob_record: OobRecord,
        alias: Optional[str] = None,
        auto_accept: Optional[bool] = None,
        mediation_id: Optional[str] = None,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> OobRecord:
        invitation = oob_record.invitation

        supported_handshake_protocols = [
            HSProto.get(DIDCommPrefix.unqualify(proto))
            for proto in invitation.handshake_protocols
        ]

        # Get the single service item
        service = invitation.services[0]
        public_did = None
        if isinstance(service, str):
            # If it's in the did format, we need to convert to a full service block
            # An existing connection can only be reused based on a public DID
            # in an out-of-band message (RFC 0434).
            # OR did:peer:2 or did:peer:4.

            if service.startswith("did:peer"):
                public_did = service
                if public_did.startswith("did:peer:4"):
                    public_did = self.long_did_peer_to_short(public_did)
            else:
                public_did = service.split(":")[-1]

            # TODO: resolve_invitation should resolve key_info objects
            # or something else that includes the key type. We now assume
            # ED25519 keys
            endpoint, recipient_keys, routing_keys = await self.resolve_invitation(
                service,
                service_accept=service_accept,
            )
            service = ServiceMessage.deserialize(
                {
                    "id": "#inline",
                    "type": "did-communication",
                    "recipientKeys": [
                        DIDKey.from_public_key_b58(key, ED25519).key_id
                        for key in recipient_keys
                    ],
                    "routingKeys": [
                        DIDKey.from_public_key_b58(key, ED25519).key_id
                        for key in routing_keys
                    ],
                    "serviceEndpoint": endpoint,
                }
            )

        if public_did:
            LOGGER.debug(f"Creating connection with public did {public_did}")
        else:
            LOGGER.debug(f"Creating connection with service {service}")

        conn_record = None
        for protocol in supported_handshake_protocols:
            # DIDExchange
            if protocol is HSProto.RFC23 or protocol is HSProto.DIDEX_1_1:
                didx_mgr = DIDXManager(self.profile)
                conn_record = await didx_mgr.receive_invitation(
                    invitation=invitation,
                    their_public_did=public_did,
                    auto_accept=auto_accept,
                    alias=alias,
                    mediation_id=mediation_id,
                    protocol=protocol.name,
                )
                break
        if not conn_record:
            raise OutOfBandManagerError(
                f"Unable to create connection. Could not perform handshake using any of "
                f"the handshake_protocols (supported {supported_handshake_protocols})"
            )

        async with self.profile.session() as session:
            oob_record.connection_id = conn_record.connection_id
            await oob_record.save(session)

        return oob_record

    async def _create_handshake_reuse_message(
        self,
        oob_record: OobRecord,
        conn_record: ConnRecord,
        version: str,
    ) -> OobRecord:
        """Create and Send a Handshake Reuse message under RFC 0434.

        Args:
            oob_record: OOB Record
            conn_record: Connection record associated with the oob record
            version: The version of the OOB protocol

        Returns:
            OobRecord: The oob record with updated state and reuse_msg_id.

        Raises:
            OutOfBandManagerError: If there is an issue creating or
            sending the OOB invitation

        """
        try:
            reuse_msg = HandshakeReuse(version=version)
            reuse_msg.assign_thread_id(thid=reuse_msg._id, pthid=oob_record.invi_msg_id)

            connection_targets = await self.fetch_connection_targets(
                connection=conn_record
            )

            responder = self.profile.inject(BaseResponder)
            await responder.send(
                message=reuse_msg,
                target_list=connection_targets,
            )

            async with self.profile.session() as session:
                oob_record.reuse_msg_id = reuse_msg._id
                oob_record.state = OobRecord.STATE_AWAIT_RESPONSE
                await oob_record.save(session, reason="Storing reuse msg data")

            return oob_record

        except Exception as err:
            raise OutOfBandManagerError(
                f"Error on creating and sending a handshake reuse message: {err}"
            )

    async def delete_stale_connection_by_invitation(self, invi_msg_id: str):
        """Delete unused connections, using existing an active connection instead."""
        tag_filter = {
            "invitation_msg_id": invi_msg_id,
        }
        post_filter = {"invitation_mode": "once", "state": "invitation"}

        async with self.profile.session() as session:
            conn_records = await ConnRecord.query(
                session,
                tag_filter=tag_filter,
                post_filter_positive=post_filter,
            )
            for conn_rec in conn_records:
                await conn_rec.delete_record(session)

    async def delete_conn_and_oob_record_invitation(self, invi_msg_id: str):
        """Delete conn_record and oob_record associated with an invi_msg_id."""
        async with self.profile.session() as session:
            conn_records = await ConnRecord.query(
                session,
                tag_filter={
                    "invitation_msg_id": invi_msg_id,
                },
                post_filter_positive={},
            )
            for conn_rec in conn_records:
                await conn_rec.delete_record(session)
            oob_records = await OobRecord.query(
                session,
                tag_filter={
                    "invi_msg_id": invi_msg_id,
                },
                post_filter_positive={},
            )
            for oob_rec in oob_records:
                await oob_rec.delete_record(session)

    async def receive_reuse_message(
        self,
        reuse_msg: HandshakeReuse,
        receipt: MessageReceipt,
        conn_rec: ConnRecord,
    ) -> None:
        """Receive and process a HandshakeReuse message under RFC 0434.

        Process a `HandshakeReuse` message by looking up
        the connection records using the MessageReceipt sender DID.

        Args:
            reuse_msg: The `HandshakeReuse` to process
            receipt: The message receipt
            conn_rec: The connection record associated with the message

        Returns:
            None

        Raises:
            OutOfBandManagerError: If the existing connection is not active
            or the connection does not exists

        """
        invi_msg_id = reuse_msg._thread.pthid
        reuse_msg_id = reuse_msg._thread_id

        reuse_accept_msg = HandshakeReuseAccept(version=reuse_msg._version)
        reuse_accept_msg.assign_thread_id(thid=reuse_msg_id, pthid=invi_msg_id)
        connection_targets = await self.fetch_connection_targets(connection=conn_rec)

        responder = self.profile.inject(BaseResponder)

        # Update ConnRecord's invi_msg_id
        async with self._profile.session() as session:
            oob_record = await OobRecord.retrieve_by_tag_filter(
                session,
                {"invi_msg_id": invi_msg_id},
                {"state": OobRecord.STATE_AWAIT_RESPONSE},
            )

            oob_record.state = OobRecord.STATE_DONE
            oob_record.reuse_msg_id = reuse_msg_id
            oob_record.connection_id = conn_rec.connection_id

            # We don't want to store this state. We either remove the record
            # (no multi-use) or we can't update the record (multi-use)
            await oob_record.emit_event(session)

            # If the oob_record is not multi-use we can now remove it
            if not oob_record.multi_use:
                await oob_record.delete_record(session)

            conn_rec.invitation_msg_id = invi_msg_id
            await conn_rec.save(session, reason="Assigning new invitation_msg_id")

        # Delete the ConnRecord created; re-use existing connection
        await self.delete_stale_connection_by_invitation(invi_msg_id)
        # Emit webhook
        await self.profile.notify(
            REUSE_WEBHOOK_TOPIC,
            {
                "thread_id": reuse_msg_id,
                "connection_id": conn_rec.connection_id,
                "comment": (
                    f"Connection {conn_rec.connection_id} is being reused "
                    f"for invitation {invi_msg_id}"
                ),
            },
        )

        await responder.send(
            message=reuse_accept_msg,
            target_list=connection_targets,
        )

    async def receive_reuse_accepted_message(
        self,
        reuse_accepted_msg: HandshakeReuseAccept,
        receipt: MessageReceipt,
        conn_record: ConnRecord,
    ) -> None:
        """Receive and process a HandshakeReuseAccept message under RFC 0434.

        Process a `HandshakeReuseAccept` message by updating the OobRecord
        state to `accepted`.

        Args:
            reuse_accepted_msg: The `HandshakeReuseAccept` to process
            receipt: The message receipt
            conn_record: The connection record associated with the message

        Returns:
            None

        Raises:
            OutOfBandManagerError: if there is an error in processing the
            HandshakeReuseAccept message

        """
        invi_msg_id = reuse_accepted_msg._thread.pthid
        thread_reuse_msg_id = reuse_accepted_msg._thread.thid

        try:
            async with self.profile.session() as session:
                oob_record = await OobRecord.retrieve_by_tag_filter(
                    session,
                    {"invi_msg_id": invi_msg_id, "reuse_msg_id": thread_reuse_msg_id},
                )

                oob_record.state = OobRecord.STATE_ACCEPTED
                oob_record.connection_id = conn_record.connection_id

                # We can now remove the oob_record
                await oob_record.emit_event(session)
                await oob_record.delete_record(session)

                conn_record.invitation_msg_id = invi_msg_id
                await conn_record.save(session, reason="Assigning new invitation_msg_id")
            # Emit webhook
            await self.profile.notify(
                REUSE_ACCEPTED_WEBHOOK_TOPIC,
                {
                    "thread_id": thread_reuse_msg_id,
                    "connection_id": conn_record.connection_id,
                    "state": "accepted",
                    "comment": (
                        f"Connection {conn_record.connection_id} is being reused "
                        f"for invitation {invi_msg_id}"
                    ),
                },
            )
        except Exception as e:
            # Emit webhook
            await self.profile.notify(
                REUSE_ACCEPTED_WEBHOOK_TOPIC,
                {
                    "thread_id": thread_reuse_msg_id,
                    "connection_id": conn_record.connection_id,
                    "state": "rejected",
                    "comment": (
                        "Unable to process HandshakeReuseAccept message, "
                        f"connection {conn_record.connection_id} "
                        f"and invitation {invi_msg_id}"
                    ),
                },
            )
            raise OutOfBandManagerError(
                (
                    "Error processing reuse accepted message "
                    f"for OOB invitation {invi_msg_id}, {e}"
                )
            )

    async def receive_problem_report(
        self,
        problem_report: OOBProblemReport,
        receipt: MessageReceipt,
        conn_record: ConnRecord,
    ) -> None:
        """Receive and process a ProblemReport message from the inviter to invitee.

        Process a `ProblemReport` message by updating the OobRecord
        state to `not_accepted`.

        Args:
            problem_report: The `OOBProblemReport` to process
            receipt: The message receipt
            conn_record: The connection record associated with the OOB record

        Returns:
            None

        Raises:
            OutOfBandManagerError: if there is an error in processing the
            HandshakeReuseAccept message

        """
        invi_msg_id = problem_report._thread.pthid
        thread_reuse_msg_id = problem_report._thread.thid
        try:
            async with self.profile.session() as session:
                oob_record = await OobRecord.retrieve_by_tag_filter(
                    session,
                    {"invi_msg_id": invi_msg_id, "reuse_msg_id": thread_reuse_msg_id},
                )
                oob_record.state = OobRecord.STATE_NOT_ACCEPTED
                await oob_record.save(session)
        except Exception as e:
            raise OutOfBandManagerError(
                (
                    "Error processing problem report message "
                    f"for OOB invitation {invi_msg_id}, {e}"
                )
            )
