"""Represents a connection request message."""

from typing import Optional

from marshmallow import EXCLUDE, fields

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from ..message_types import CONNECTION_REQUEST, PROTOCOL_PACKAGE
from ..models.connection_detail import ConnectionDetail, ConnectionDetailSchema

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.connection_request_handler.ConnectionRequestHandler"
)


class ConnectionRequest(AgentMessage):
    """Class representing a connection request."""

    class Meta:
        """Metadata for a connection request."""

        handler_class = HANDLER_CLASS
        message_type = CONNECTION_REQUEST
        schema_class = "ConnectionRequestSchema"

    def __init__(
        self,
        *,
        connection: Optional[ConnectionDetail] = None,
        label: Optional[str] = None,
        image_url: Optional[str] = None,
        **kwargs,
    ):
        """Initialize connection request object.

        Args:
            connection (ConnectionDetail): Connection details object
            label: Label for this connection request
            image_url: Optional image URL for this connection request
            kwargs: Additional keyword arguments for the message

        """
        super().__init__(**kwargs)
        self.connection = connection
        self.label = label
        self.image_url = image_url


class ConnectionRequestSchema(AgentMessageSchema):
    """Connection request schema class."""

    class Meta:
        """Connection request schema metadata."""

        model_class = ConnectionRequest
        unknown = EXCLUDE

    connection = fields.Nested(ConnectionDetailSchema, required=True)
    label = fields.Str(
        required=True,
        metadata={
            "description": "Label for connection request",
            "example": "Request to connect with Bob",
        },
    )
    image_url = fields.Str(
        data_key="imageUrl",
        required=False,
        allow_none=True,
        metadata={
            "description": "Optional image URL for connection request",
            "example": "http://192.168.56.101/img/logo.jpg",
        },
    )
