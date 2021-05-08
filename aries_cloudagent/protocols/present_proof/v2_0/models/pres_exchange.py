"""Presentation exchange record."""

from typing import Any, Mapping, Union

from marshmallow import fields, Schema, validate

from .....messaging.models import to_serial
from .....messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from .....messaging.valid import UUIDFour

from ..messages.pres import V20Pres, V20PresSchema
from ..messages.pres_format import V20PresFormat
from ..messages.pres_proposal import V20PresProposal, V20PresProposalSchema
from ..messages.pres_request import V20PresRequest, V20PresRequestSchema

from . import UNENCRYPTED_TAGS


class V20PresExRecord(BaseExchangeRecord):
    """Represents a v2.0 presentation exchange."""

    class Meta:
        """V20PresExRecord metadata."""

        schema_class = "V20PresExRecordSchema"

    RECORD_TYPE = "pres_ex_v20"
    RECORD_ID_NAME = "pres_ex_id"
    RECORD_TOPIC = "present_proof_v2_0"
    TAG_NAMES = {"~thread_id"} if UNENCRYPTED_TAGS else {"thread_id"}

    INITIATOR_SELF = "self"
    INITIATOR_EXTERNAL = "external"

    ROLE_PROVER = "prover"
    ROLE_VERIFIER = "verifier"

    STATE_PROPOSAL_SENT = "proposal-sent"
    STATE_PROPOSAL_RECEIVED = "proposal-received"
    STATE_REQUEST_SENT = "request-sent"
    STATE_REQUEST_RECEIVED = "request-received"
    STATE_PRESENTATION_SENT = "presentation-sent"
    STATE_PRESENTATION_RECEIVED = "presentation-received"
    STATE_DONE = "done"
    STATE_ABANDONED = "abandoned"

    def __init__(
        self,
        *,
        pres_ex_id: str = None,
        connection_id: str = None,
        thread_id: str = None,
        initiator: str = None,
        role: str = None,
        state: str = None,
        pres_proposal: Union[V20PresProposal, Mapping] = None,  # aries message
        pres_request: Union[V20PresRequest, Mapping] = None,  # aries message
        pres: Union[V20Pres, Mapping] = None,  # aries message
        verified: str = None,
        auto_present: bool = False,
        error_msg: str = None,
        trace: bool = False,  # backward compat: BaseRecord.FromStorage()
        by_format: Mapping = None,  # backward compat: BaseRecord.FromStorage()
        **kwargs
    ):
        """Initialize a new PresExRecord."""
        super().__init__(pres_ex_id, state, trace=trace, **kwargs)
        self.connection_id = connection_id
        self.thread_id = thread_id
        self.initiator = initiator
        self.role = role
        self.state = state
        self.pres_proposal = to_serial(pres_proposal)
        self.pres_request = to_serial(pres_request)
        self.pres = to_serial(pres)
        self.verified = verified
        self.auto_present = auto_present
        self.error_msg = error_msg

    @property
    def pres_ex_id(self) -> str:
        """Accessor for the ID associated with this exchange record."""
        return self._id

    @property
    def by_format(self) -> Mapping:
        """Record proposal, request, and presentation attachments by format."""
        result = {}
        for item, cls in {
            "pres_proposal": V20PresProposal,  # note: proof request attached for indy
            "pres_request": V20PresRequest,
            "pres": V20Pres,
        }.items():
            mapping = to_serial(getattr(self, item))
            if mapping:
                msg = cls.deserialize(mapping)
                result.update(
                    {
                        item: {
                            V20PresFormat.Format.get(f.format).api: msg.attachment(
                                V20PresFormat.Format.get(f.format)
                            )
                            for f in msg.formats
                        }
                    }
                )

        return result

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this pres ex record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "initiator",
                "role",
                "state",
                "pres_proposal",
                "pres_request",
                "pres",
                "verified",
                "auto_present",
                "error_msg",
                "trace",
            )
        }

    def serialize(self, as_string=False) -> Mapping:
        """
        Create a JSON-compatible representation of the model instance.

        Args:
            as_string: return a string of JSON instead of a mapping

        """
        copy = V20PresExRecord(
            pres_ex_id=self.pres_ex_id,
            **{
                k: v
                for k, v in vars(self).items()
                if k
                not in [
                    "_id",
                    "_last_state",
                    "pres_proposal",
                    "pres_request",
                    "pres",
                ]
            }
        )
        copy.pres_proposal = V20PresProposal.deserialize(
            self.pres_proposal,
            none2none=True,
        )
        copy.pres_request = V20PresRequest.deserialize(
            self.pres_request,
            none2none=True,
        )
        copy.pres = V20Pres.deserialize(self.pres, none2none=True)

        return super(self.__class__, copy).serialize(as_string)

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class V20PresExRecordSchema(BaseExchangeSchema):
    """Schema for de/serialization of v2.0 presentation exchange records."""

    class Meta:
        """V20PresExRecordSchema metadata."""

        model_class = V20PresExRecord

    pres_ex_id = fields.Str(
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
        example=V20PresExRecord.INITIATOR_SELF,
        validate=validate.OneOf(
            [
                getattr(V20PresExRecord, m)
                for m in vars(V20PresExRecord)
                if m.startswith("INITIATOR_")
            ]
        ),
    )
    role = fields.Str(
        required=False,
        description="Present-proof exchange role: prover or verifier",
        example=V20PresExRecord.ROLE_PROVER,
        validate=validate.OneOf(
            [
                getattr(V20PresExRecord, m)
                for m in vars(V20PresExRecord)
                if m.startswith("ROLE_")
            ]
        ),
    )
    state = fields.Str(
        required=False,
        description="Present-proof exchange state",
        validate=validate.OneOf(
            [
                getattr(V20PresExRecord, m)
                for m in vars(V20PresExRecord)
                if m.startswith("STATE_")
            ]
        ),
    )
    pres_proposal = fields.Nested(
        V20PresProposalSchema(),
        required=False,
        description="Presentation proposal message",
    )
    pres_request = fields.Nested(
        V20PresRequestSchema(),
        required=False,
        description="Presentation request message",
    )
    pres = fields.Nested(
        V20PresSchema(),
        required=False,
        description="Presentation message",
    )
    by_format = fields.Nested(
        Schema.from_dict(
            {
                "pres_proposal": fields.Dict(required=False),
                "pres_request": fields.Dict(required=False),
                "pres": fields.Dict(required=False),
            }
        ),
        required=False,
        description=(
            "Attachment content by format for proposal, request, and presentation"
        ),
        dump_only=True,
    )
    verified = fields.Str(  # tag: must be a string
        required=False,
        description="Whether presentation is verified: 'true' or 'false'",
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
