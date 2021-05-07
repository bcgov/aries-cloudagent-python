"""DIF Proof Request Schema"""
from marshmallow import fields, validate, validates_schema, ValidationError
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import UUID4
from .pres_exch import PresentationDefinitionSchema


class DIFPresRequestSchema(OpenAPISchema):
    """Schema for DIF pres request."""

    challenge = fields.String(
        description="Challenge protect against replay attack",
        required=False,
        **UUID4,
        data_key="challenge",
    )
    
    domain = fields.String(
        description="Domain protect against replay attack",
        required=False,
        data_key="domain",
        example="4jt78h47fh47",
    )   
    
    presentation_definition = fields.Nested(
        PresentationDefinitionSchema(),
        required=False,
        data_key="presentation_definition",
    )