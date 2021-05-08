"""Aries#0037 v1.0 presentation exchange information with non-secrets storage."""

from typing import Any, Mapping, Union

from marshmallow import fields, validate

from .....indy.sdk.models.proof import IndyProof, IndyProofSchema
from .....indy.sdk.models.proof_request import IndyProofRequest, IndyProofRequestSchema
from .....messaging.models import to_serial
from .....messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from .....messaging.valid import UUIDFour

from ..messages.presentation_proposal import (
    PresentationProposal,
    PresentationProposalSchema,
)
from ..messages.presentation_request import (
    PresentationRequest,
    PresentationRequestSchema,
)

from . import UNENCRYPTED_TAGS


class V10PresentationExchange(BaseExchangeRecord):
    """Represents an Aries#0037 v1.0 presentation exchange."""

    class Meta:
        """V10PresentationExchange metadata."""

        schema_class = "V10PresentationExchangeSchema"

    RECORD_TYPE = "presentation_exchange_v10"
    RECORD_ID_NAME = "presentation_exchange_id"
    RECORD_TOPIC = "present_proof"
    TAG_NAMES = {"~thread_id"} if UNENCRYPTED_TAGS else {"thread_id"}

    INITIATOR_SELF = "self"
    INITIATOR_EXTERNAL = "external"

    ROLE_PROVER = "prover"
    ROLE_VERIFIER = "verifier"

    STATE_PROPOSAL_SENT = "proposal_sent"
    STATE_PROPOSAL_RECEIVED = "proposal_received"
    STATE_REQUEST_SENT = "request_sent"
    STATE_REQUEST_RECEIVED = "request_received"
    STATE_PRESENTATION_SENT = "presentation_sent"
    STATE_PRESENTATION_RECEIVED = "presentation_received"
    STATE_VERIFIED = "verified"
    STATE_PRESENTATION_ACKED = "presentation_acked"

    def __init__(
        self,
        *,
        presentation_exchange_id: str = None,
        connection_id: str = None,
        thread_id: str = None,
        initiator: str = None,
        role: str = None,
        state: str = None,
        presentation_proposal_dict: Union[
            PresentationProposal, Mapping
        ] = None,  # aries message
        presentation_request: Union[IndyProofRequest, Mapping] = None,  # indy proof req
        presentation_request_dict: Union[
            PresentationRequest, Mapping
        ] = None,  # aries message
        presentation: Union[IndyProof, Mapping] = None,  # indy proof
        verified: str = None,
        auto_present: bool = False,
        error_msg: str = None,
        trace: bool = False,  # backward compat: BaseRecord.from_storage()
        **kwargs
    ):
        """Initialize a new PresentationExchange."""
        super().__init__(presentation_exchange_id, state, trace=trace, **kwargs)
        self.connection_id = connection_id
        self.thread_id = thread_id
        self.initiator = initiator
        self.role = role
        self.state = state
        self.presentation_proposal_dict = to_serial(presentation_proposal_dict)
        self.presentation_request = to_serial(presentation_request)
        self.presentation_request_dict = to_serial(presentation_request_dict)
        self.presentation = to_serial(presentation)
        self.verified = verified
        self.auto_present = auto_present
        self.error_msg = error_msg

    @property
    def presentation_exchange_id(self) -> str:
        """Accessor for the ID associated with this exchange."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this presentation exchange."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "initiator",
                "presentation_proposal_dict",
                "presentation_request",
                "presentation_request_dict",
                "presentation",
                "role",
                "state",
                "auto_present",
                "error_msg",
                "verified",
                "trace",
            )
        }

    def serialize(self, as_string=False) -> Mapping:
        """
        Create a JSON-compatible representation of the model instance.

        Args:
            as_string: return a string of JSON instead of a mapping

        """
        copy = V10PresentationExchange(
            presentation_exchange_id=self.presentation_exchange_id,
            **{
                k: v
                for k, v in vars(self).items()
                if k
                not in [
                    "_id",
                    "_last_state",
                    "presentation_proposal_dict",
                    "presentation_request",
                    "presentation_request_dict",
                    "presentation",
                ]
            }
        )
        copy.presentation_proposal_dict = PresentationProposal.deserialize(
            self.presentation_proposal_dict,
            none2none=True,
        )
        copy.presentation_request = IndyProofRequest.deserialize(
            self.presentation_request,
            none2none=True,
        )
        copy.presentation_request_dict = PresentationRequest.deserialize(
            self.presentation_request_dict,
            none2none=True,
        )
        copy.presentation = IndyProof.deserialize(self.presentation, none2none=True)
        return super(self.__class__, copy).serialize(as_string)

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class V10PresentationExchangeSchema(BaseExchangeSchema):
    """Schema for de/serialization of v1.0 presentation exchange records."""

    class Meta:
        """V10PresentationExchangeSchema metadata."""

        model_class = V10PresentationExchange

    presentation_exchange_id = fields.Str(
        required=False,
        description="Presentation exchange identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    connection_id = fields.Str(
        required=False,
        description="Connection identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    thread_id = fields.Str(
        required=False,
        description="Thread identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    initiator = fields.Str(
        required=False,
        description="Present-proof exchange initiator: self or external",
        example=V10PresentationExchange.INITIATOR_SELF,
        validate=validate.OneOf(["self", "external"]),
    )
    role = fields.Str(
        required=False,
        description="Present-proof exchange role: prover or verifier",
        example=V10PresentationExchange.ROLE_PROVER,
        validate=validate.OneOf(["prover", "verifier"]),
    )
    state = fields.Str(
        required=False,
        description="Present-proof exchange state",
        example=V10PresentationExchange.STATE_VERIFIED,
    )
    presentation_proposal_dict = fields.Nested(
        PresentationProposalSchema(),
        required=False,
        description="Presentation proposal message",
    )
    presentation_request = fields.Nested(
        IndyProofRequestSchema(),
        required=False,
        description="(Indy) presentation request (also known as proof request)",
    )
    presentation_request_dict = fields.Nested(
        PresentationRequestSchema(),
        required=False,
        description="Presentation request message",
    )
    presentation = fields.Nested(
        IndyProofSchema(),
        required=False,
        description="(Indy) presentation (also known as proof)",
    )
    verified = fields.Str(  # tag: must be a string
        required=False,
        description="Whether presentation is verified: true or false",
        example="true",
        validate=validate.OneOf(["true", "false"]),
    )
    auto_present = fields.Bool(
        required=False,
        description="Prover choice to auto-present proof as verifier requests",
        example=False,
    )
    error_msg = fields.Str(
        required=False, description="Error message", example="Invalid structure"
    )
