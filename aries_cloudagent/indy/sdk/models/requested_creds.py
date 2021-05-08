"""Admin routes for presentations."""

from marshmallow import fields

from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import INT_EPOCH


class IndyRequestedCredsRequestedAttrSchema(OpenAPISchema):
    """Schema for requested attributes within indy requested credentials structure."""

    cred_id = fields.Str(
        example="3fa85f64-5717-4562-b3fc-2c963f66afa6",
        description=(
            "Wallet credential identifier (typically but not necessarily a UUID)"
        ),
        required=True,
    )
    revealed = fields.Bool(
        description="Whether to reveal attribute in proof (default true)", default=True
    )


class IndyRequestedCredsRequestedPredSchema(OpenAPISchema):
    """Schema for requested predicates within indy requested credentials structure."""

    cred_id = fields.Str(
        description=(
            "Wallet credential identifier (typically but not necessarily a UUID)"
        ),
        example="3fa85f64-5717-4562-b3fc-2c963f66afa6",
        required=True,
    )
    timestamp = fields.Int(
        description="Epoch timestamp of interest for non-revocation proof",
        required=False,
        strict=True,
        **INT_EPOCH,
    )
