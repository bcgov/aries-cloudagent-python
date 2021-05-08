"""Aries#0036 v1.0 credential exchange information with non-secrets storage."""

from typing import Any, Mapping, Union

from marshmallow import fields, validate

from .....core.profile import ProfileSession
from .....indy.sdk.models.cred import IndyCredential, IndyCredentialSchema
from .....indy.sdk.models.cred_abstract import IndyCredAbstract, IndyCredAbstractSchema
from .....indy.sdk.models.cred_precis import IndyCredInfo, IndyCredInfoSchema
from .....indy.sdk.models.cred_request import IndyCredRequest, IndyCredRequestSchema
from .....messaging.models import to_serial
from .....messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from .....messaging.valid import INDY_CRED_DEF_ID, INDY_SCHEMA_ID, UUIDFour

from ..messages.credential_proposal import CredentialProposal, CredentialProposalSchema
from ..messages.credential_offer import CredentialOffer, CredentialOfferSchema

from . import UNENCRYPTED_TAGS


class V10CredentialExchange(BaseExchangeRecord):
    """Represents an Aries#0036 credential exchange."""

    class Meta:
        """CredentialExchange metadata."""

        schema_class = "V10CredentialExchangeSchema"

    RECORD_TYPE = "credential_exchange_v10"
    RECORD_ID_NAME = "credential_exchange_id"
    RECORD_TOPIC = "issue_credential"
    TAG_NAMES = {"~thread_id"} if UNENCRYPTED_TAGS else {"thread_id"}

    INITIATOR_SELF = "self"
    INITIATOR_EXTERNAL = "external"
    ROLE_ISSUER = "issuer"
    ROLE_HOLDER = "holder"

    STATE_PROPOSAL_SENT = "proposal_sent"
    STATE_PROPOSAL_RECEIVED = "proposal_received"
    STATE_OFFER_SENT = "offer_sent"
    STATE_OFFER_RECEIVED = "offer_received"
    STATE_REQUEST_SENT = "request_sent"
    STATE_REQUEST_RECEIVED = "request_received"
    STATE_ISSUED = "credential_issued"
    STATE_CREDENTIAL_RECEIVED = "credential_received"
    STATE_ACKED = "credential_acked"

    def __init__(
        self,
        *,
        credential_exchange_id: str = None,
        connection_id: str = None,
        thread_id: str = None,
        parent_thread_id: str = None,
        initiator: str = None,
        role: str = None,
        state: str = None,
        credential_definition_id: str = None,
        schema_id: str = None,
        credential_proposal_dict: Union[
            Mapping, CredentialProposal
        ] = None,  # aries message
        credential_offer_dict: Union[Mapping, CredentialOffer] = None,  # aries message
        credential_offer: Union[Mapping, IndyCredAbstract] = None,  # indy artifact
        credential_request: [Mapping, IndyCredRequest] = None,  # indy artifact
        credential_request_metadata: Mapping = None,
        credential_id: str = None,
        raw_credential: Union[Mapping, IndyCredential] = None,  # indy cred as received
        credential: Union[Mapping, IndyCredInfo] = None,  # indy cred as stored
        revoc_reg_id: str = None,
        revocation_id: str = None,
        auto_offer: bool = False,
        auto_issue: bool = False,
        auto_remove: bool = True,
        error_msg: str = None,
        trace: bool = False,  # backward-compat: BaseRecord.from_storage()
        **kwargs,
    ):
        """Initialize a new V10CredentialExchange."""
        super().__init__(credential_exchange_id, state, trace=trace, **kwargs)
        self._id = credential_exchange_id
        self.connection_id = connection_id
        self.thread_id = thread_id
        self.parent_thread_id = parent_thread_id
        self.initiator = initiator
        self.role = role
        self.state = state
        self.credential_definition_id = credential_definition_id
        self.schema_id = schema_id
        self.credential_proposal_dict = to_serial(credential_proposal_dict)
        self.credential_offer_dict = to_serial(credential_offer_dict)
        self.credential_offer = to_serial(credential_offer)
        self.credential_request = to_serial(credential_request)
        self.credential_request_metadata = credential_request_metadata
        self.credential_id = credential_id
        self.raw_credential = to_serial(raw_credential)
        self.credential = to_serial(credential)
        self.revoc_reg_id = revoc_reg_id
        self.revocation_id = revocation_id
        self.auto_offer = auto_offer
        self.auto_issue = auto_issue
        self.auto_remove = auto_remove
        self.error_msg = error_msg

    @property
    def credential_exchange_id(self) -> str:
        """Accessor for the ID associated with this exchange."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for the JSON record value generated for this credential exchange."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "credential_proposal_dict",
                "credential_offer_dict",
                "credential_offer",
                "credential_request",
                "credential_request_metadata",
                "error_msg",
                "auto_offer",
                "auto_issue",
                "auto_remove",
                "raw_credential",
                "credential",
                "parent_thread_id",
                "initiator",
                "credential_definition_id",
                "schema_id",
                "credential_id",
                "revoc_reg_id",
                "revocation_id",
                "role",
                "state",
                "trace",
            )
        }

    def serialize(self, as_string=False) -> Mapping:
        """
        Create a JSON-compatible representation of the model instance.

        Args:
            as_string: return a string of JSON instead of a mapping

        """
        copy = V10CredentialExchange(
            credential_exchange_id=self.credential_exchange_id,
            **{
                k: v
                for k, v in vars(self).items()
                if k
                not in [
                    "_id",
                    "_last_state",
                    "credential_proposal_dict",
                    "credential_offer_dict",
                    "credential_offer",
                    "credential_request",
                    "raw_credential",
                    "credential",
                ]
            },
        )
        copy.credential_proposal_dict = CredentialProposal.deserialize(
            self.credential_proposal_dict,
            none2none=True,
        )
        copy.credential_offer_dict = CredentialOffer.deserialize(
            self.credential_offer_dict,
            none2none=True,
        )
        copy.credential_offer = IndyCredAbstract.deserialize(
            self.credential_offer,
            none2none=True,
        )
        copy.credential_request = IndyCredRequest.deserialize(
            self.credential_request,
            none2none=True,
        )
        copy.raw_credential = IndyCredential.deserialize(
            self.raw_credential,
            none2none=True,
        )
        copy.credential = IndyCredInfo.deserialize(self.credential, none2none=True)

        return super(self.__class__, copy).serialize(as_string)

    @classmethod
    async def retrieve_by_connection_and_thread(
        cls, session: ProfileSession, connection_id: str, thread_id: str
    ) -> "V10CredentialExchange":
        """Retrieve a credential exchange record by connection and thread ID."""
        cache_key = f"credential_exchange_ctidx::{connection_id}::{thread_id}"
        record_id = await cls.get_cached_key(session, cache_key)
        if record_id:
            record = await cls.retrieve_by_id(session, record_id)
        else:
            record = await cls.retrieve_by_tag_filter(
                session,
                {"thread_id": thread_id},
                {"connection_id": connection_id} if connection_id else None,
            )
            await cls.set_cached_key(session, cache_key, record.credential_exchange_id)
        return record

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class V10CredentialExchangeSchema(BaseExchangeSchema):
    """Schema to allow serialization/deserialization of credential exchange records."""

    class Meta:
        """V10CredentialExchangeSchema metadata."""

        model_class = V10CredentialExchange

    credential_exchange_id = fields.Str(
        required=False,
        description="Credential exchange identifier",
        example=UUIDFour.EXAMPLE,
    )
    connection_id = fields.Str(
        required=False, description="Connection identifier", example=UUIDFour.EXAMPLE
    )
    thread_id = fields.Str(
        required=False, description="Thread identifier", example=UUIDFour.EXAMPLE
    )
    parent_thread_id = fields.Str(
        required=False, description="Parent thread identifier", example=UUIDFour.EXAMPLE
    )
    initiator = fields.Str(
        required=False,
        description="Issue-credential exchange initiator: self or external",
        example=V10CredentialExchange.INITIATOR_SELF,
        validate=validate.OneOf(["self", "external"]),
    )
    role = fields.Str(
        required=False,
        description="Issue-credential exchange role: holder or issuer",
        example=V10CredentialExchange.ROLE_ISSUER,
        validate=validate.OneOf(["holder", "issuer"]),
    )
    state = fields.Str(
        required=False,
        description="Issue-credential exchange state",
        example=V10CredentialExchange.STATE_ACKED,
    )
    credential_definition_id = fields.Str(
        required=False,
        description="Credential definition identifier",
        **INDY_CRED_DEF_ID,
    )
    schema_id = fields.Str(
        required=False, description="Schema identifier", **INDY_SCHEMA_ID
    )
    credential_proposal_dict = fields.Nested(
        CredentialProposalSchema(),
        required=False,
        description="Credential proposal message",
    )
    credential_offer_dict = fields.Nested(
        CredentialOfferSchema(),
        required=False,
        description="Credential offer message",
    )
    credential_offer = fields.Nested(
        IndyCredAbstractSchema(),
        required=False,
        description="(Indy) credential offer",
    )
    credential_request = fields.Nested(
        IndyCredRequestSchema(),
        required=False,
        description="(Indy) credential request",
    )
    credential_request_metadata = fields.Dict(
        required=False, description="(Indy) credential request metadata"
    )
    credential_id = fields.Str(
        required=False, description="Credential identifier", example=UUIDFour.EXAMPLE
    )
    raw_credential = fields.Nested(
        IndyCredentialSchema(),
        required=False,
        description="Credential as received, prior to storage in holder wallet",
    )
    credential = fields.Nested(
        IndyCredInfoSchema(),
        required=False,
        description="Credential as stored",
    )
    auto_offer = fields.Bool(
        required=False,
        description="Holder choice to accept offer in this credential exchange",
        example=False,
    )
    auto_issue = fields.Bool(
        required=False,
        description="Issuer choice to issue to request in this credential exchange",
        example=False,
    )
    auto_remove = fields.Bool(
        required=False,
        default=True,
        description=(
            "Issuer choice to remove this credential exchange record when complete"
        ),
        example=False,
    )
    error_msg = fields.Str(
        required=False,
        description="Error message",
        example="Credential definition identifier is not set in proposal",
    )
    revoc_reg_id = fields.Str(
        required=False, description="Revocation registry identifier"
    )
    revocation_id = fields.Str(
        required=False, description="Credential identifier within revocation registry"
    )
