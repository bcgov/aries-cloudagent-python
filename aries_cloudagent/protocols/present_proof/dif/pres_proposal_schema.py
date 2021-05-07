"""DIF Proof Request Schema"""
from marshmallow import fields, validate, validates_schema, ValidationError
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import UUID4
from .pres_exch import ConstraintsSchema, SchemaInputDescriptorSchema


class DIFPresProposalSchema(OpenAPISchema):
    """Schema for DIF pres proposal."""

    id = fields.Str(description="ID", required=False, data_key="id")
    groups = fields.List(
        fields.Str(
            description="Group",
            required=False,
        ),
        required=False,
        data_key="group",
    )
    name = fields.Str(description="Name", required=False, data_key="name")
    purpose = fields.Str(description="Purpose", required=False, data_key="purpose")
    metadata = fields.Dict(
        description="Metadata dictionary", required=False, data_key="metadata"
    )
    constraint = fields.Nested(
        ConstraintsSchema, required=False, data_key="constraints"
    )
    schemas = fields.List(
        fields.Nested(SchemaInputDescriptorSchema), required=False, data_key="schema"
    )
