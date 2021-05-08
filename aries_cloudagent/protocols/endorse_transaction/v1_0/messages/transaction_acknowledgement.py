"""Represents a transaction acknowledgement message."""

from marshmallow import EXCLUDE, fields

from .....messaging.valid import UUIDFour
from .....messaging.ack.message import Ack, AckSchema

from ..message_types import TRANSACTION_ACKNOWLEDGEMENT, PROTOCOL_PACKAGE

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".transaction_acknowledgement_handler.TransactionAcknowledgementHandler"
)


class TransactionAcknowledgement(Ack):
    """Class representing a transaction acknowledgement message."""

    class Meta:
        """Metadata for a transaction acknowledgement message."""

        handler_class = HANDLER_CLASS
        message_type = TRANSACTION_ACKNOWLEDGEMENT
        schema_class = "TransactionAcknowledgementSchema"

    def __init__(
        self,
        *,
        thread_id: str = None,
        **kwargs,
    ):
        """
        Initialize a transaction acknowledgement object.

        Args:
            thread_id: Thread id of transaction record
        """
        super().__init__(**kwargs)
        self.thread_id = thread_id


class TransactionAcknowledgementSchema(AckSchema):
    """Transaction Acknowledgement schema class."""

    class Meta:
        """Transaction Acknowledgement metadata."""

        model_class = TransactionAcknowledgement
        unknown = EXCLUDE

    thread_id = fields.Str(required=True, example=UUIDFour.EXAMPLE)
