"""Credential format inner object."""

from collections import namedtuple
from enum import Enum
from typing import Mapping, Sequence, Type, Union
from uuid import uuid4

from marshmallow import EXCLUDE, fields

from .....utils.classloader import DeferLoad
from .....messaging.decorators.attach_decorator import AttachDecorator
from .....messaging.models.base import BaseModel, BaseModelSchema
from .....messaging.valid import UUIDFour
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..formats.handler import V20PresFormatHandler

# aries prefix
FormatSpec = namedtuple("FormatSpec", "aries handler")


class V20PresFormat(BaseModel):
    """Present-proof protocol message attachment format."""

    class Meta:
        """Present-proof protocol message attachment format metadata."""

        schema_class = "V20PresFormatSchema"

    class Format(Enum):
        """Attachment format."""

        INDY = FormatSpec(
            "hlindy/",
            DeferLoad(
                "aries_cloudagent.protocols.present_proof.v2_0"
                ".formats.indy.handler.IndyPresExchangeHandler"
            ),
        )
        DIF = FormatSpec(
            "dif/",
            DeferLoad(
                "aries_cloudagent.protocols.present_proof.v2_0"
                ".formats.dif.handler.DIFPresExchangeHandler"
            ),
        )

        @classmethod
        def get(cls, label: Union[str, "V20PresFormat.Format"]):
            """Get format enum for label."""
            if isinstance(label, str):
                for fmt in V20PresFormat.Format:
                    if label.startswith(fmt.aries) or label == fmt.api:
                        return fmt
            elif isinstance(label, V20PresFormat.Format):
                return label

            return None

        @property
        def api(self) -> str:
            """Admin API specifier."""
            return self.name.lower()

        @property
        def aries(self) -> str:
            """Accessor for aries identifier."""
            return self.value.aries

        @property
        def handler(self) -> Type["V20PresFormatHandler"]:
            """Accessor for presentation exchange format handler."""
            return self.value.handler.resolved

        def validate_fields(self, message_type: str, attachment_data: Mapping):
            """Raise ValidationError for invalid attachment formats."""
            self.handler.validate_fields(message_type, attachment_data)

        def get_attachment_data(
            self,
            formats: Sequence["V20PresFormat"],
            attachments: Sequence[AttachDecorator],
        ):
            """Find attachment of current format, decode and return its content."""
            for fmt in formats:
                if V20PresFormat.Format.get(fmt.format) is self:
                    attach_id = fmt.attach_id
                    break
            else:
                return None

            for atch in attachments:
                if atch.ident == attach_id:
                    return atch.content

            return None

    def __init__(
        self,
        *,
        attach_id: str = None,
        format_: str = None,
    ):
        """Initialize present-proof protocol message attachment format."""
        self.attach_id = attach_id or uuid4()
        self.format_ = format_

    @property
    def format(self) -> str:
        """Return format."""
        return self.format_


class V20PresFormatSchema(BaseModelSchema):
    """Present-proof protocol message attachment format schema."""

    class Meta:
        """Present-proof protocol message attachment format schema metadata."""

        model_class = V20PresFormat
        unknown = EXCLUDE

    attach_id = fields.Str(
        required=True,
        allow_none=False,
        description="Attachment identifier",
        example=UUIDFour.EXAMPLE,
    )
    format_ = fields.Str(
        required=True,
        allow_none=False,
        description="Attachment format specifier",
        data_key="format",
        example="dif/presentation-exchange/submission@v1.0",
    )
