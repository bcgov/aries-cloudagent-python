"""Admin routes for presentations."""

from typing import Mapping

from marshmallow import EXCLUDE, fields

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import (
    INDY_CRED_DEF_ID,
    INDY_CRED_REV_ID,
    INDY_REV_REG_ID,
    INDY_SCHEMA_ID,
    UUIDFour,
)

from .non_rev_interval import IndyNonRevocationIntervalSchema


class IndyCredInfo(BaseModel):
    """Indy cred info, as holder gets via indy-sdk."""

    class Meta:
        """IndyCredInfo metadata."""

        schema_class = "IndyCredInfoSchema"

    def __init__(
        self,
        referent: str = None,
        attrs: Mapping = None,
        schema_id: str = None,
        cred_def_id: str = None,
        rev_reg_id: str = None,
        cred_rev_id: str = None,
    ):
        """Initialize indy cred info."""
        self.referent = referent
        self.attrs = attrs
        self.schema_id = schema_id
        self.cred_def_id = cred_def_id
        self.rev_reg_id = rev_reg_id
        self.cred_rev_id = cred_rev_id


class IndyCredInfoSchema(BaseModelSchema):
    """Schema for indy cred-info."""

    class Meta:
        """Schema metadata."""

        model_class = IndyCredInfo
        unknown = EXCLUDE

    referent = fields.Str(
        description="Wallet referent",
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    attrs = fields.Dict(
        description="Attribute names and value",
        keys=fields.Str(example="userid"),  # marshmallow/apispec v3.0 ignores
        values=fields.Str(example="alice"),
    )
    schema_id = fields.Str(
        description="Schema identifier",
        **INDY_SCHEMA_ID,
    )
    cred_def_id = fields.Str(
        description="Credential definition identifier",
        **INDY_CRED_DEF_ID,
    )
    rev_reg_id = fields.Str(
        description="Revocation registry identifier",
        **INDY_REV_REG_ID,
        allow_none=True,
    )
    cred_rev_id = fields.Str(
        description="Credential revocation identifier",
        **INDY_CRED_REV_ID,
        allow_none=True,
    )


class IndyCredPrecisSchema(OpenAPISchema):
    """Schema for precis that indy credential search returns (and aca-py augments)."""

    cred_info = fields.Nested(
        IndyCredInfoSchema(),
        description="Credential info",
    )
    interval = fields.Nested(
        IndyNonRevocationIntervalSchema(),
        description="Non-revocation interval from presentation request",
    )
    pres_referents = fields.List(  # aca-py augments with pres_referents
        fields.Str(
            description="presentation referent",
            example="1_age_uuid",
        ),
    )
