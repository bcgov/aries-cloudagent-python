"""Handle connection information interface with non-secrets storage."""

import json
from enum import Enum
from typing import Any, Optional, Union, List

from marshmallow import fields, validate

from ...core.profile import ProfileSession
from ...messaging.models.base_record import BaseRecord, BaseRecordSchema
from ...messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    RAW_ED25519_2018_PUBLIC_KEY_EXAMPLE,
    RAW_ED25519_2018_PUBLIC_KEY_VALIDATE,
    UUID4_EXAMPLE,
)
from ...protocols.connections.v1_0.message_types import ARIES_PROTOCOL as CONN_PROTO
from ...protocols.connections.v1_0.message_types import (
    CONNECTION_INVITATION,
    CONNECTION_REQUEST,
)
from ...protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitation,
)
from ...protocols.connections.v1_0.messages.connection_request import ConnectionRequest
from ...protocols.didcomm_prefix import DIDCommPrefix
from ...protocols.didexchange.v1_0.message_types import ARIES_PROTOCOL as DIDEX_1_1
from ...protocols.didexchange.v1_0.message_types import DIDEX_1_0
from ...protocols.didexchange.v1_0.messages.request import DIDXRequest
from ...protocols.out_of_band.v1_0.messages.invitation import (
    InvitationMessage as OOBInvitation,
)
from ...storage.base import BaseStorage
from ...storage.error import StorageNotFoundError
from ...storage.record import StorageRecord


class PeerwiseRecord(BaseRecord):
    """Represents a single pairwise connection."""

    class Meta:
        """ConnRecord metadata."""

        schema_class = "MaybeStoredConnRecordSchema"

    SUPPORTED_PROTOCOLS = (CONN_PROTO, DIDEX_1_0, DIDEX_1_1)

    class Role(Enum):
        """RFC 160 (inviter, invitee) = RFC 23 (responder, requester)."""

        REQUESTER = ("invitee", "requester")  # == RFC 23 initiator, RFC 434 receiver
        RESPONDER = ("inviter", "responder")  # == RFC 160 initiator(!), RFC 434 sender

        @property
        def rfc160(self):
            """Return RFC 160 (connection protocol) nomenclature."""
            return self.value[0]

        @property
        def rfc23(self):
            """Return RFC 23 (DID exchange protocol) nomenclature."""
            return self.value[1]

        @classmethod
        def get(cls, label: Union[str, "ConnRecord.Role"]):
            """Get role enum for label."""
            if isinstance(label, str):
                for role in ConnRecord.Role:
                    if label in role.value:
                        return role
            elif isinstance(label, ConnRecord.Role):
                return label
            return None

        def flip(self):
            """Return opposite interlocutor role: theirs for ours, ours for theirs."""
            return (
                ConnRecord.Role.REQUESTER
                if self is ConnRecord.Role.RESPONDER
                else ConnRecord.Role.RESPONDER
            )

        def __eq__(self, other: Union[str, "ConnRecord.Role"]) -> bool:
            """Comparison between roles."""
            return self is ConnRecord.Role.get(other)

    class State(Enum):
        """Collator for equivalent states between RFC 160 and RFC 23.

        On the connection record, the state has to serve for both RFCs.
        Hence, internally, RFC23 requester/responder states collate to
        their RFC160 condensed equivalent.
        """

        INIT = ("init", "start")
        INVITATION = ("invitation", "invitation")
        REQUEST = ("request", "request")
        RESPONSE = ("response", "response")
        COMPLETED = ("active", "completed")
        ABANDONED = ("error", "abandoned")

        @property
        def rfc160(self):
            """Return RFC 160 (connection protocol) nomenclature."""
            return self.value[0]

        @property
        def rfc23(self):
            """Return RFC 23 (DID exchange protocol) nomenclature to record logic."""
            return self.value[1]

        def rfc23strict(self, their_role: "ConnRecord.Role"):
            """Return RFC 23 (DID exchange protocol) nomenclature to role as per RFC."""

            if not their_role or self in (
                ConnRecord.State.INIT,
                ConnRecord.State.COMPLETED,
                ConnRecord.State.ABANDONED,
            ):
                return self.value[1]

            if self is ConnRecord.State.REQUEST:
                return self.value[1] + (
                    "-sent"
                    if ConnRecord.Role.get(their_role) is ConnRecord.Role.RESPONDER
                    else "-received"
                )
            else:
                return self.value[1] + (
                    "-received"
                    if ConnRecord.Role.get(their_role) is ConnRecord.Role.RESPONDER
                    else "-sent"
                )

        @classmethod
        def get(cls, label: Union[str, "ConnRecord.State"]):
            """Get state enum for label."""
            if isinstance(label, str):
                for state in ConnRecord.State:
                    if label in state.value:
                        return state
            elif isinstance(label, ConnRecord.State):
                return label
            return None

        def __eq__(self, other: Union[str, "ConnRecord.State"]) -> bool:
            """Comparison between states."""
            return self is ConnRecord.State.get(other)

    RECORD_ID_NAME = "pairwise_id"
    RECORD_TOPIC = "peer_connections"
    LOG_STATE_FLAG = "debug.connections"
    TAG_NAMES = {
        "my_did",
        "their_did",
        #"request_id",
        "invitation_msg_id",
    }

    RECORD_TYPE = "peer_connection"
    RECORD_TYPE_INVITATION = "connection_invitation"
    RECORD_TYPE_REQUEST = "connection_request"
    RECORD_TYPE_METADATA = "connection_metadata"

    INVITATION_MODE_ONCE = "once"
    INVITATION_MODE_MULTI = "multi"
    INVITATION_MODE_STATIC = "static"

    ACCEPT_MANUAL = "manual"
    ACCEPT_AUTO = "auto"

    def __init__(
        self,
        *,
        pairwise_id: Optional[str] = None,
        my_did: Optional[str] = None,
        their_did: Optional[str] = None,
        #their_label: Optional[str] = None,
        invitation_msg_id: Optional[str] = None,
        accept: Optional[str] = None,
        alias: Optional[str] = None,
        aka: Optional[List[str]] = None,
        **kwargs,
    ):
        """Initialize a new ConnRecord."""
        super().__init__(
            pairwise_id,
            **kwargs,
        )
        self.my_did = my_did
        self.their_did = their_did
        #self.their_label = their_label
        self.invitation_msg_id = invitation_msg_id
        self.accept = accept or self.ACCEPT_MANUAL
        self.alias = alias
        self.aka = aka

    @property
    def pairwise_id(self) -> str:
        """Accessor for the ID associated with this connection."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor to for the JSON record value properties for this connection."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "accept",
                "invitation_msg_id",
                "alias",
                #"their_label",
            )
        }

    @classmethod
    async def retrieve_by_did(
        cls,
        session: ProfileSession,
        their_did: Optional[str] = None,
        my_did: Optional[str] = None,
        their_role: Optional[str] = None,
    ) -> "ConnRecord":
        """Retrieve a connection record by target DID.

        Args:
            session: The active profile session
            their_did: The target DID to filter by
            my_did: One of our DIDs to filter by
            my_role: Filter connections by their role
            their_role: Filter connections by their role
        """
        tag_filter = {}
        if their_did:
            tag_filter["their_did"] = their_did
        if my_did:
            tag_filter["my_did"] = my_did

        post_filter = {}
        if their_role:
            post_filter["their_role"] = cls.Role.get(their_role).rfc160

        return await cls.retrieve_by_tag_filter(session, tag_filter, post_filter)

    @classmethod
    async def retrieve_by_did_peer_4(
        cls,
        session: ProfileSession,
        their_did_long: Optional[str] = None,
        their_did_short: Optional[str] = None,
        my_did: Optional[str] = None,
        their_role: Optional[str] = None,
    ) -> "ConnRecord":
        """Retrieve a connection record by target DID.

        Args:
            session: The active profile session
            their_did_long: The target DID to filter by, in long form
            their_did_short: The target DID to filter by, in short form
            my_did: One of our DIDs to filter by
            my_role: Filter connections by their role
            their_role: Filter connections by their role
        """
        tag_filter = {}
        if their_did_long and their_did_short:
            tag_filter["$or"] = [
                {"their_did": their_did_long},
                {"their_did": their_did_short},
            ]
        elif their_did_short:
            tag_filter["their_did"] = their_did_short
        elif their_did_long:
            tag_filter["their_did"] = their_did_long
        if my_did:
            tag_filter["my_did"] = my_did

        post_filter = {}
        if their_role:
            post_filter["their_role"] = cls.Role.get(their_role).rfc160

        return await cls.retrieve_by_tag_filter(session, tag_filter, post_filter)

    @classmethod
    async def retrieve_by_invitation_key(
        cls,
        session: ProfileSession,
        invitation_key: str,
        their_role: Optional[str] = None,
    ) -> "ConnRecord":
        """Retrieve a connection record by invitation key.

        Args:
            session: The active profile session
            invitation_key: The key on the originating invitation
            their_role: Filter by their role
        """
        tag_filter = {
            "invitation_key": invitation_key,
            "state": cls.State.INVITATION.rfc160,
        }
        post_filter = {"state": cls.State.INVITATION.rfc160}

        if their_role:
            post_filter["their_role"] = cls.Role.get(their_role).rfc160
            tag_filter["their_role"] = cls.Role.get(their_role).rfc160

        return await cls.retrieve_by_tag_filter(session, tag_filter, post_filter)

    @classmethod
    async def retrieve_by_invitation_msg_id(
        cls,
        session: ProfileSession,
        invitation_msg_id: str,
        their_role: Optional[str] = None,
    ) -> Optional["ConnRecord"]:
        """Retrieve a connection record by invitation_msg_id.

        Args:
            session: The active profile session
            invitation_msg_id: Invitation message identifier
            their_role: Filter by their role
        """
        tag_filter = {"invitation_msg_id": invitation_msg_id}
        post_filter = {
            "state": cls.State.INVITATION.rfc160,
        }
        if their_role:
            post_filter["their_role"] = cls.Role.get(their_role).rfc160
        try:
            return await cls.retrieve_by_tag_filter(session, tag_filter, post_filter)
        except StorageNotFoundError:
            return None

    @classmethod
    async def retrieve_by_request_id(
        cls, session: ProfileSession, request_id: str, their_role: Optional[str] = None
    ) -> "ConnRecord":
        """Retrieve a connection record from our previous request ID.

        Args:
            session: The active profile session
            request_id: The ID of the originating connection request
            their_role: Filter by their role
        """
        tag_filter = {"request_id": request_id}
        if their_role:
            tag_filter["their_role"] = their_role
        return await cls.retrieve_by_tag_filter(session, tag_filter)

    @classmethod
    async def retrieve_by_alias(cls, session: ProfileSession, alias: str) -> "ConnRecord":
        """Retrieve a connection record from an alias.

        Args:
            session: The active profile session
            alias: The alias of the connection
        """
        post_filter = {"alias": alias}
        return await cls.query(session, post_filter_positive=post_filter)

    async def attach_invitation(
        self,
        session: ProfileSession,
        invitation: Union[ConnectionInvitation, OOBInvitation],
    ):
        """Persist the related connection invitation to storage.

        Args:
            session: The active profile session
            invitation: The invitation to relate to this connection record
        """
        assert self.pairwise_id
        record = StorageRecord(
            self.RECORD_TYPE_INVITATION,  # conn- or oob-invitation, to retrieve easily
            invitation.to_json(),
            {"pairwise_id": self.pairwise_id},
        )
        storage = session.inject(BaseStorage)
        await storage.add_record(record)

    async def retrieve_invitation(
        self, session: ProfileSession
    ) -> Union[ConnectionInvitation, OOBInvitation]:
        """Retrieve the related connection invitation.

        Args:
            session: The active profile session
        """
        assert self.pairwise_id
        storage = session.inject(BaseStorage)
        result = await storage.find_record(
            self.RECORD_TYPE_INVITATION,
            {"pairwise_id": self.pairwise_id},
        )
        ser = json.loads(result.value)
        return (
            ConnectionInvitation
            if DIDCommPrefix.unqualify(ser["@type"]) == CONNECTION_INVITATION
            else OOBInvitation
        ).deserialize(ser)

    async def attach_request(
        self,
        session: ProfileSession,
        request: Union[ConnectionRequest, DIDXRequest],
    ):
        """Persist the related connection request to storage.

        Args:
            session: The active profile session
            request: The request to relate to this connection record
        """
        assert self.pairwise_id
        record = StorageRecord(
            self.RECORD_TYPE_REQUEST,  # conn- or didx-request, to retrieve easily
            request.to_json(),
            {"pairwise_id": self.pairwise_id},
        )
        storage: BaseStorage = session.inject(BaseStorage)
        await storage.add_record(record)

    async def retrieve_request(
        self,
        session: ProfileSession,
    ) -> Union[ConnectionRequest, DIDXRequest]:
        """Retrieve the related connection invitation.

        Args:
            session: The active profile session
        """
        assert self.pairwise_id
        storage: BaseStorage = session.inject(BaseStorage)
        result = await storage.find_record(
            self.RECORD_TYPE_REQUEST, {"pairwise_id": self.pairwise_id}
        )
        ser = json.loads(result.value)
        return (
            ConnectionRequest
            if DIDCommPrefix.unqualify(ser["@type"]) == CONNECTION_REQUEST
            else DIDXRequest
        ).deserialize(ser)

    @property
    def is_ready(self) -> str:
        """Accessor for connection readiness."""
        return ConnRecord.State.get(self.state) in (
            ConnRecord.State.COMPLETED,
            ConnRecord.State.RESPONSE,
        )

    @property
    def is_multiuse_invitation(self) -> bool:
        """Accessor for multi use invitation mode."""
        return self.invitation_mode == self.INVITATION_MODE_MULTI

    async def post_save(self, session: ProfileSession, *args, **kwargs):
        """Perform post-save actions.

        Args:
            session: The active profile session
            args: Additional positional arguments
            kwargs: Additional keyword arguments
        """
        await super().post_save(session, *args, **kwargs)

        # clear cache key set by connection manager
        cache_key = f"pairwise_connection::{self.pairwise_id}"
        await self.clear_cached_key(session, cache_key)

    async def delete_record(self, session: ProfileSession):
        """Perform connection record deletion actions.

        Args:
            session (ProfileSession): session

        """
        await super().delete_record(session)

        storage = session.inject(BaseStorage)
        # Delete metadata
        if self.pairwise_id:
            await storage.delete_all_records(
                self.RECORD_TYPE_METADATA,
                {"pairwise_id": self.pairwise_id},
            )

        # Delete attached messages
        await storage.delete_all_records(
            self.RECORD_TYPE_REQUEST,
            {"pairwise_id": self.pairwise_id},
        )
        await storage.delete_all_records(
            self.RECORD_TYPE_INVITATION,
            {"pairwise_id": self.pairwise_id},
        )

    async def abandon(self, session: ProfileSession, *, reason: Optional[str] = None):
        """Set state to abandoned."""
        reason = reason or "Connection abandoned"
        self.state = ConnRecord.State.ABANDONED.rfc160
        self.error_msg = reason
        await self.save(session, reason=reason)

    async def metadata_get(
        self, session: ProfileSession, key: str, default: Optional[Any] = None
    ) -> Any:
        """Retrieve arbitrary metadata associated with this connection.

        Args:
            session (ProfileSession): session used for storage
            key (str): key identifying metadata
            default (Any): default value to get; type should be a JSON
                compatible value.

        Returns:
            Any: metadata stored by key

        """
        assert self.pairwise_id
        storage: BaseStorage = session.inject(BaseStorage)
        try:
            record = await storage.find_record(
                self.RECORD_TYPE_METADATA,
                {"key": key, "pairwise_id": self.pairwise_id},
            )
            return json.loads(record.value)
        except StorageNotFoundError:
            return default

    async def metadata_set(self, session: ProfileSession, key: str, value: Any):
        """Set arbitrary metadata associated with this connection.

        Args:
            session (ProfileSession): session used for storage
            key (str): key identifying metadata
            value (Any): value to set
        """
        assert self.pairwise_id
        value = json.dumps(value)
        storage: BaseStorage = session.inject(BaseStorage)
        try:
            record = await storage.find_record(
                self.RECORD_TYPE_METADATA,
                {"key": key, "pairwise_id": self.pairwise_id},
            )
            await storage.update_record(record, value, record.tags)
        except StorageNotFoundError:
            record = StorageRecord(
                self.RECORD_TYPE_METADATA,
                value,
                {"key": key, "pairwise_id": self.pairwise_id},
            )
            await storage.add_record(record)

    async def metadata_delete(self, session: ProfileSession, key: str):
        """Delete custom metadata associated with this connection.

        Args:
            session (ProfileSession): session used for storage
            key (str): key of metadata to delete
        """
        assert self.pairwise_id
        storage: BaseStorage = session.inject(BaseStorage)
        try:
            record = await storage.find_record(
                self.RECORD_TYPE_METADATA,
                {"key": key, "pairwise_id": self.pairwise_id},
            )
            await storage.delete_record(record)
        except StorageNotFoundError as err:
            raise KeyError(f"{key} not found in connection metadata") from err

    async def metadata_get_all(self, session: ProfileSession) -> dict:
        """Return all custom metadata associated with this connection.

        Args:
            session (ProfileSession): session used for storage

        Returns:
            dict: dictionary representation of all metadata values

        """
        assert self.pairwise_id
        storage: BaseStorage = session.inject(BaseStorage)
        records = await storage.find_all_records(
            self.RECORD_TYPE_METADATA,
            {"pairwise_id": self.pairwise_id},
        )
        return {record.tags["key"]: json.loads(record.value) for record in records}

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class MaybeStoredConnRecordSchema(BaseRecordSchema):
    """Schema to allow serialization/deserialization of connection records."""

    class Meta:
        """MaybeStoredConnRecordSchema metadata."""

        model_class = PeerwiseRecord

    pairwise_id = fields.Str(
        required=False,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )
    my_did = fields.Str(
        required=False,
        validate=GENERIC_DID_VALIDATE,
        metadata={
            "description": "Our DID for connection",
            "example": GENERIC_DID_EXAMPLE,
        },
    )
    their_did = fields.Str(
        required=False,
        validate=GENERIC_DID_VALIDATE,
        metadata={
            "description": "Their DID for connection",
            "example": GENERIC_DID_EXAMPLE,
        },
    )
    #their_label = fields.Str(
    #    required=False,
    #    metadata={"description": "Their label for connection", "example": "Bob"},
    #)
    invitation_msg_id = fields.Str(
        required=False,
        metadata={
            "description": "ID of out-of-band invitation message",
            "example": UUID4_EXAMPLE,
        },
    )
    accept = fields.Str(
        required=False,
        validate=validate.OneOf(
            PeerwiseRecord.get_attributes_by_prefix("ACCEPT_", walk_mro=False)
        ),
        metadata={
            "description": "Connection acceptance: manual or auto",
            "example": PeerwiseRecord.ACCEPT_AUTO,
        },
    )
    alias = fields.Str(
        required=False,
        metadata={
            "description": "Optional alias to apply to connection for later use",
            "example": "Bob, providing quotes",
        },
    )
    aka = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "Optional list of DIDs that this peer-wise contact is known as",
            "example": ["did:example:bob", "did:example:bob-phone"],
        },
    )



class PeerwiseRecordSchema(MaybeStoredConnRecordSchema):
    """Schema representing stored ConnRecords."""

    class Meta:
        """ConnRecordSchema metadata."""

        model_class = PeerwiseRecord

    pairwise_id = fields.Str(
        required=True,
        metadata={"description": "Connection identifier", "example": UUID4_EXAMPLE},
    )
