"""A presentation proposal content message."""

from typing import Sequence

from marshmallow import EXCLUDE, fields, RAISE, validates_schema, ValidationError

from .....indy.sdk.models.proof_request import IndyProofRequestSchema
from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.decorators.attach_decorator import (
    AttachDecorator,
    AttachDecoratorSchema,
)

from ..message_types import PRES_20_PROPOSAL, PROTOCOL_PACKAGE

from .pres_format import V20PresFormat, V20PresFormatSchema

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.pres_proposal_handler.V20PresProposalHandler"
)


class V20PresProposal(AgentMessage):
    """Class representing a presentation proposal."""

    class Meta:
        """V20PresProposal metadata."""

        handler_class = HANDLER_CLASS
        schema_class = "V20PresProposalSchema"
        message_type = PRES_20_PROPOSAL

    def __init__(
        self,
        _id: str = None,
        *,
        comment: str = None,
        formats: Sequence[V20PresFormat] = None,
        proposals_attach: Sequence[AttachDecorator] = None,
        **kwargs,
    ):
        """
        Initialize pres proposal object.

        Args:
            comment: optional human-readable comment
            formats: acceptable attachment formats
            proposals_attach: proposal attachments specifying criteria by format
        """
        super().__init__(_id, **kwargs)
        self.comment = comment
        self.formats = list(formats) if formats else []
        self.proposals_attach = list(proposals_attach) if proposals_attach else []

    def attachment(self, fmt: V20PresFormat.Format = None) -> dict:
        """
        Return attached proposal item.

        Args:
            fmt: format of attachment in list to decode and return

        """
        target_format = (
            fmt
            if fmt
            else next(
                filter(
                    lambda ff: ff,
                    [V20PresFormat.Format.get(f.format) for f in self.formats],
                ),
                None,
            )
        )
        return (
            target_format.get_attachment_data(self.formats, self.proposals_attach)
            if target_format
            else None
        )


class V20PresProposalSchema(AgentMessageSchema):
    """Presentation proposal schema."""

    class Meta:
        """Presentation proposal schema metadata."""

        model_class = V20PresProposal
        unknown = EXCLUDE

    comment = fields.Str(description="Human-readable comment", required=False)
    formats = fields.Nested(
        V20PresFormatSchema,
        many=True,
        required=True,
        descrption="Acceptable attachment formats",
    )
    proposals_attach = fields.Nested(
        AttachDecoratorSchema,
        many=True,
        required=True,
        data_key="proposals~attach",
        description="Attachment per acceptable format on corresponding identifier",
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate proposal attachment per format."""

        def get_attach_by_id(attach_id):
            """Return attachment with input attachment identifier."""
            for atch in attachments:
                if atch.ident == attach_id:
                    return atch
            raise ValidationError(f"No attachment for attach_id {attach_id} in formats")

        formats = data.get("formats") or []
        attachments = data.get("proposals_attach") or []
        if len(formats) != len(attachments):
            raise ValidationError("Formats/attachments length mismatch")

        for fmt in formats:
            atch = get_attach_by_id(fmt.attach_id)
            if V20PresFormat.Format.get(fmt.format) is V20PresFormat.Format.INDY:
                IndyProofRequestSchema(unknown=RAISE).load(atch.content)
