"""Represents a connection response message."""

from typing import Optional

from marshmallow import EXCLUDE, fields

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from ..message_types import CONNECTION_RESPONSE, PROTOCOL_PACKAGE
from ..models.connection_detail import ConnectionDetail, ConnectionDetailSchema

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.connection_response_handler.ConnectionResponseHandler"
)


class ConnectionResponse(AgentMessage):
    """Class representing a connection response."""

    class Meta:
        """Metadata for a connection response."""

        handler_class = HANDLER_CLASS
        schema_class = "ConnectionResponseSchema"
        message_type = CONNECTION_RESPONSE

    def __init__(self, *, connection: Optional[ConnectionDetail] = None, **kwargs):
        """Initialize connection response object.

        Args:
            connection: Connection details object
            kwargs: Additional keyword arguments for the message

        """
        super().__init__(**kwargs)
        self.connection = connection


class ConnectionResponseSchema(AgentMessageSchema):
    """Connection response schema class."""

    class Meta:
        """Connection response schema metadata."""

        model_class = ConnectionResponse
        signed_fields = ("connection",)
        unknown = EXCLUDE

    connection = fields.Nested(ConnectionDetailSchema, required=True)
