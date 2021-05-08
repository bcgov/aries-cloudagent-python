"""Schema artifacts."""

from marshmallow import fields

from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import INDY_SCHEMA_ID, INDY_VERSION, NATURAL_NUM


class SchemaSchema(OpenAPISchema):
    """Marshmallow schema for indy schema."""

    ver = fields.Str(description="Node protocol version", **INDY_VERSION)
    ident = fields.Str(data_key="id", description="Schema identifier", **INDY_SCHEMA_ID)
    name = fields.Str(
        description="Schema name",
        example=INDY_SCHEMA_ID["example"].split(":")[2],
    )
    version = fields.Str(description="Schema version", **INDY_VERSION)
    attr_names = fields.List(
        fields.Str(
            description="Attribute name",
            example="score",
        ),
        description="Schema attribute names",
        data_key="attrNames",
    )
    seqNo = fields.Int(description="Schema sequence number", strict=True, **NATURAL_NUM)
