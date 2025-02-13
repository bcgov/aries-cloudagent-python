"""Represents an invitation message for establishing connection."""

from typing import Optional, Sequence
from urllib.parse import parse_qs, urljoin, urlparse

from marshmallow import EXCLUDE, ValidationError, fields, pre_load, validates_schema

from .....did.did_key import DIDKey
from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.valid import (
    GENERIC_DID_EXAMPLE,
    GENERIC_DID_VALIDATE,
    RAW_ED25519_2018_PUBLIC_KEY_EXAMPLE,
    RAW_ED25519_2018_PUBLIC_KEY_VALIDATE,
)
from .....wallet.util import b64_to_bytes, bytes_to_b64
from ..message_types import CONNECTION_INVITATION, PROTOCOL_PACKAGE

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".connection_invitation_handler.ConnectionInvitationHandler"
)


class ConnectionInvitation(AgentMessage):
    """Class representing a connection invitation."""

    class Meta:
        """Metadata for a connection invitation."""

        handler_class = HANDLER_CLASS
        message_type = CONNECTION_INVITATION
        schema_class = "ConnectionInvitationSchema"

    def __init__(
        self,
        *,
        label: Optional[str] = None,
        did: Optional[str] = None,
        recipient_keys: Sequence[str] = None,
        endpoint: Optional[str] = None,
        routing_keys: Sequence[str] = None,
        image_url: Optional[str] = None,
        **kwargs,
    ):
        """Initialize connection invitation object.

        Args:
            label: Optional label for connection invitation
            did: DID for this connection invitation
            recipient_keys: List of recipient keys
            endpoint: Endpoint which this agent can be reached at
            routing_keys: List of routing keys
            image_url: Optional image URL for connection invitation
            kwargs: Additional keyword arguments for the message
        """
        super().__init__(**kwargs)
        self.label = label
        self.did = did
        self.recipient_keys = list(recipient_keys) if recipient_keys else None
        self.endpoint = endpoint
        self.routing_keys = list(routing_keys) if routing_keys else None
        self.routing_keys = (
            [
                (
                    DIDKey.from_did(key).public_key_b58
                    if key.startswith("did:key:")
                    else key
                )
                for key in self.routing_keys
            ]
            if self.routing_keys
            else None
        )
        self.image_url = image_url

    def to_url(self, base_url: Optional[str] = None) -> str:
        """Convert an invitation to URL format for sharing.

        Returns:
            An invite url

        """
        c_json = self.to_json()
        c_i = bytes_to_b64(c_json.encode("ascii"), urlsafe=True, pad=False)
        result = urljoin(base_url or self.endpoint or "", "?c_i={}".format(c_i))
        return result

    @classmethod
    def from_url(cls, url: str) -> "ConnectionInvitation":
        """Parse a URL-encoded invitation into a `ConnectionInvitation` message.

        Args:
            url: Url to decode

        Returns:
            A `ConnectionInvitation` object.

        """
        parts = urlparse(url)
        query = parse_qs(parts.query)
        if "c_i" in query:
            c_i = b64_to_bytes(query["c_i"][0], urlsafe=True)
            return cls.from_json(c_i)
        return None


class ConnectionInvitationSchema(AgentMessageSchema):
    """Connection invitation schema class."""

    class Meta:
        """Connection invitation schema metadata."""

        model_class = ConnectionInvitation
        unknown = EXCLUDE

    label = fields.Str(
        required=False,
        metadata={
            "description": "Optional label for connection invitation",
            "example": "Bob",
        },
    )
    did = fields.Str(
        required=False,
        validate=GENERIC_DID_VALIDATE,
        metadata={
            "description": "DID for connection invitation",
            "example": GENERIC_DID_EXAMPLE,
        },
    )
    recipient_keys = fields.List(
        fields.Str(
            validate=RAW_ED25519_2018_PUBLIC_KEY_VALIDATE,
            metadata={
                "description": "Recipient public key",
                "example": RAW_ED25519_2018_PUBLIC_KEY_EXAMPLE,
            },
        ),
        data_key="recipientKeys",
        required=False,
        metadata={"description": "List of recipient keys"},
    )
    endpoint = fields.Str(
        data_key="serviceEndpoint",
        required=False,
        metadata={
            "description": "Service endpoint at which to reach this agent",
            "example": "http://192.168.56.101:8020",
        },
    )
    routing_keys = fields.List(
        fields.Str(
            validate=RAW_ED25519_2018_PUBLIC_KEY_VALIDATE,
            metadata={
                "description": "Routing key",
                "example": RAW_ED25519_2018_PUBLIC_KEY_EXAMPLE,
            },
        ),
        data_key="routingKeys",
        required=False,
        metadata={"description": "List of routing keys"},
    )
    image_url = fields.URL(
        data_key="imageUrl",
        required=False,
        allow_none=True,
        metadata={
            "description": "Optional image URL for connection invitation",
            "example": "http://192.168.56.101/img/logo.jpg",
        },
    )

    @pre_load
    def transform_routing_keys(self, data, **kwargs):
        """Transform routingKeys from did:key refs, if necessary."""
        routing_keys = data.get("routingKeys")
        if routing_keys:
            data["routingKeys"] = [
                (
                    DIDKey.from_did(key).public_key_b58
                    if key.startswith("did:key:")
                    else key
                )
                for key in routing_keys
            ]
        return data

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields.

        Args:
            data: The data to validate
            kwargs: Additional keyword arguments

        Raises:
            ValidationError: If any of the fields do not validate

        """
        if data.get("did"):
            if data.get("recipient_keys"):
                raise ValidationError("Fields are incompatible", ("did", "recipientKeys"))
            if data.get("endpoint"):
                raise ValidationError(
                    "Fields are incompatible", ("did", "serviceEndpoint")
                )
        elif not data.get("recipient_keys") or not data.get("endpoint"):
            raise ValidationError(
                "Missing required field(s)", ("did", "recipientKeys", "serviceEndpoint")
            )
