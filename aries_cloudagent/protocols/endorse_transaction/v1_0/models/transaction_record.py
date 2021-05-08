"""Handle transaction information interface."""

from marshmallow import fields

from .....messaging.models.base_record import (
    BaseExchangeRecord,
    BaseExchangeSchema,
)

from .....messaging.valid import UUIDFour

from .....core.profile import ProfileSession


class TransactionRecord(BaseExchangeRecord):
    """Represents a single transaction record."""

    class Meta:
        """Transaction Record metadata."""

        schema_class = "TransactionRecordSchema"

    RECORD_ID_NAME = "transaction_id"
    CACHE_ENABLED = True
    TAG_NAMES = {"state", "thread_id", "connection_id"}
    RECORD_TYPE = "transaction"
    STATE_INIT = "init"
    RECORD_TOPIC = "endorse_transaction"

    SIGNATURE_REQUEST = "http://didcomm.org/sign-attachment/%VER/signature-request"

    SIGNATURE_RESPONSE = "http://didcomm.org/sign-attachment/%VER/signature-response"

    SIGNATURE_TYPE = "<requested signature type>"

    SIGNATURE_CONTEXT = "did:sov"

    ADD_SIGNATURE = "add-signature"

    ENDORSE_TRANSACTION = "transaction.endorse"
    REFUSE_TRANSACTION = "transaction.refuse"
    WRITE_TRANSACTION = "transaction.ledger.write"

    FORMAT_VERSION = "dif/endorse-transaction/request@v1.0"

    STATE_TRANSACTION_CREATED = "transaction_created"
    STATE_REQUEST_SENT = "request_sent"
    STATE_REQUEST_RECEIVED = "request_received"
    STATE_TRANSACTION_ENDORSED = "transaction_endorsed"
    STATE_TRANSACTION_REFUSED = "transaction_refused"
    STATE_TRANSACTION_RESENT = "transaction_resent"
    STATE_TRANSACTION_RESENT_RECEIEVED = "transaction_resent_received"
    STATE_TRANSACTION_CANCELLED = "transaction_cancelled"
    STATE_TRANSACTION_COMPLETED = "transaction_completed"

    def __init__(
        self,
        *,
        transaction_id: str = None,
        _type: str = None,
        comment: str = None,
        signature_request: list = None,
        signature_response: list = None,
        timing: dict = None,
        formats: list = None,
        messages_attach: list = None,
        thread_id: str = None,
        connection_id: str = None,
        state: str = None,
        **kwargs,
    ):
        """Initialize a new TransactionRecord."""

        super().__init__(transaction_id, state or self.STATE_INIT, **kwargs)
        self._type = _type
        self.comment = comment
        self.signature_request = signature_request or []
        self.signature_response = signature_response or []
        self.timing = timing or {}
        self.formats = formats or []
        self.messages_attach = messages_attach or []
        self.thread_id = thread_id
        self.connection_id = connection_id

    @property
    def transaction_id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for the JSON record value generated for this transaction record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "comment",
                "signature_request",
                "signature_response",
                "timing",
                "formats",
                "messages_attach",
                "thread_id",
                "connection_id",
                "state",
            )
        }

    @classmethod
    async def retrieve_by_connection_and_thread(
        cls, session: ProfileSession, connection_id: str, thread_id: str
    ) -> "TransactionRecord":
        """Retrieve a TransactionRecord by connection and thread ID."""
        cache_key = f"transaction_record_ctidx::{connection_id}::{thread_id}"
        record_id = await cls.get_cached_key(session, cache_key)
        if record_id:
            record = await cls.retrieve_by_id(session, record_id)
        else:
            record = await cls.retrieve_by_tag_filter(
                session,
                {"thread_id": thread_id},
                {"connection_id": connection_id} if connection_id else None,
            )
            await cls.set_cached_key(session, cache_key, record._id)
        return record


class TransactionRecordSchema(BaseExchangeSchema):
    """Schema to allow serialization/deserialization of transaction records."""

    class Meta:
        """TransactionRecordSchema metadata."""

        model_class = "TransactionRecord"

    transaction_id = fields.Str(
        required=False, description="Transaction identifier", example=UUIDFour.EXAMPLE
    )
    _type = fields.Str(
        required=False,
        description="Transaction type",
        example="101",
    )
    signature_request = fields.List(
        fields.Dict(
            example={
                "context": TransactionRecord.SIGNATURE_CONTEXT,
                "method": TransactionRecord.ADD_SIGNATURE,
                "signature_type": TransactionRecord.SIGNATURE_TYPE,
                "signer_goal_code": TransactionRecord.ENDORSE_TRANSACTION,
                "author_goal_code": TransactionRecord.WRITE_TRANSACTION,
            }
        ),
        required=False,
    )
    signature_response = fields.List(
        fields.Dict(
            example={
                "message_id": UUIDFour.EXAMPLE,
                "context": TransactionRecord.SIGNATURE_CONTEXT,
                "method": TransactionRecord.ADD_SIGNATURE,
                "signer_goal_code": TransactionRecord.REFUSE_TRANSACTION,
            }
        ),
        required=False,
    )
    timing = fields.Dict(
        example={"expires_time": "2020-12-13T17:29:06+0000"}, required=False
    )
    formats = fields.List(
        fields.Dict(
            keys=fields.Str(),
            values=fields.Str(),
            example={
                "attach_id": UUIDFour.EXAMPLE,
                "format": TransactionRecord.FORMAT_VERSION,
            },
        ),
        required=False,
    )
    messages_attach = fields.List(
        fields.Dict(
            example={
                "@id": "143c458d-1b1c-40c7-ab85-4d16808ddf0a",
                "mime-type": "application/json",
                "data": {
                    "json": "{"
                    '"endorser": "V4SGRU86Z58d6TV7PBUe6f",'
                    '"identifier": "LjgpST2rjsoxYegQDRm7EL",'
                    '"operation": {'
                    '"data": {'
                    '"attr_names": ["first_name", "last_name"],'
                    '"name": "test_schema",'
                    '"version": "2.1",'
                    "},"
                    '"type": "101",'
                    "},"
                    '"protocolVersion": 2,'
                    '"reqId": 1597766666168851000,'
                    '"signatures": {'
                    '"LjgpST2rjsox": "4ATKMn6Y9sTgwqaGTm7py2c2M8x1EVDTWKZArwyuPgjU"'
                    "},"
                    '"taaAcceptance": {'
                    '"mechanism": "manual",'
                    '"taaDigest": "f50fe2c2ab977006761d36bd6f23e4c6a7e0fc2feb9f62",'
                    '"time": 1597708800,'
                    "}"
                    "}"
                },
            }
        ),
        required=False,
    )
    thread_id = fields.Str(
        required=False, description="Thread Identifier", example=UUIDFour.EXAMPLE
    )
    connection_id = fields.Str(
        required=False,
        description="The connection identifier for thie particular transaction record",
        example=UUIDFour.EXAMPLE,
    )
