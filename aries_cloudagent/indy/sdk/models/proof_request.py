"""Utilities to deal with indy."""

from typing import Mapping

from marshmallow import (
    EXCLUDE,
    fields,
    Schema,
    validate,
    validates_schema,
    ValidationError,
)

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import (
    INDY_CRED_DEF_ID,
    INDY_DID,
    INDY_PREDICATE,
    INDY_SCHEMA_ID,
    INDY_VERSION,
    INT_EPOCH,
    NUM_STR_NATURAL,
)


class IndyProofReqPredSpecRestrictionsSchema(OpenAPISchema):
    """Schema for restrictions in attr or pred specifier indy proof request."""

    schema_id = fields.Str(
        description="Schema identifier", required=False, **INDY_SCHEMA_ID
    )
    schema_issuer_did = fields.Str(
        description="Schema issuer (origin) DID", required=False, **INDY_DID
    )
    schema_name = fields.Str(
        example="transcript", description="Schema name", required=False
    )
    schema_version = fields.Str(
        description="Schema version", required=False, **INDY_VERSION
    )
    issuer_did = fields.Str(
        description="Credential issuer DID", required=False, **INDY_DID
    )
    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=False,
        **INDY_CRED_DEF_ID,
    )


class IndyProofReqAttrSpecSchema(OpenAPISchema):
    """Schema for attribute specification in indy proof request."""

    name = fields.Str(
        example="favouriteDrink", description="Attribute name", required=False
    )
    names = fields.List(
        fields.Str(example="age"),
        description="Attribute name group",
        required=False,
    )
    restrictions = fields.List(
        fields.Dict(
            keys=fields.Str(
                validate=validate.Regexp(
                    "^schema_id|"
                    "schema_issuer_did|"
                    "schema_name|"
                    "schema_version|"
                    "issuer_did|"
                    "cred_def_id|"
                    "attr::.+::value$"  # indy does not support attr::...::marker here
                ),
                example="cred_def_id",  # marshmallow/apispec v3.0 ignores
            ),
            values=fields.Str(example=INDY_CRED_DEF_ID["example"]),
        ),
        description=(
            "If present, credential must satisfy one of given restrictions: specify "
            "schema_id, schema_issuer_did, schema_name, schema_version, "
            "issuer_did, cred_def_id, and/or attr::<attribute-name>::value "
            "where <attribute-name> represents a credential attribute name"
        ),
        required=False,
    )
    non_revoked = fields.Nested(
        Schema.from_dict(
            {
                "from": fields.Int(
                    required=False,
                    description="Earliest time of interest in non-revocation interval",
                    strict=True,
                    **INT_EPOCH,
                ),
                "to": fields.Int(
                    required=False,
                    description="Latest time of interest in non-revocation interval",
                    strict=True,
                    **INT_EPOCH,
                ),
            }
        ),
        allow_none=True,  # accommodate libvcx
        required=False,
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """
        Validate schema fields.

        Data must have exactly one of name or names; if names then restrictions are
        mandatory.

        Args:
            data: The data to validate

        Raises:
            ValidationError: if data has both or neither of name and names

        """
        if ("name" in data) == ("names" in data):
            raise ValidationError(
                "Attribute specification must have either name or names but not both"
            )
        restrictions = data.get("restrictions")
        if ("names" in data) and (not restrictions or all(not r for r in restrictions)):
            raise ValidationError(
                "Attribute specification on 'names' must have non-empty restrictions"
            )


class IndyProofReqPredSpecSchema(OpenAPISchema):
    """Schema for predicate specification in indy proof request."""

    name = fields.Str(example="index", description="Attribute name", required=True)
    p_type = fields.Str(
        description="Predicate type ('<', '<=', '>=', or '>')",
        required=True,
        **INDY_PREDICATE,
    )
    p_value = fields.Int(description="Threshold value", required=True, strict=True)
    restrictions = fields.List(
        fields.Nested(IndyProofReqPredSpecRestrictionsSchema()),
        description="If present, credential must satisfy one of given restrictions",
        required=False,
    )
    non_revoked = fields.Nested(
        Schema.from_dict(
            {
                "from": fields.Int(
                    required=False,
                    description="Earliest time of interest in non-revocation interval",
                    strict=True,
                    **INT_EPOCH,
                ),
                "to": fields.Int(
                    required=False,
                    description="Latest time of interest in non-revocation interval",
                    strict=True,
                    **INT_EPOCH,
                ),
            }
        ),
        allow_none=True,  # accommodate libvcx
        required=False,
    )


class IndyProofRequest(BaseModel):
    """Indy proof request."""

    class Meta:
        """Indy proof request metadata."""

        schema_class = "IndyProofRequestSchema"

    def __init__(
        self,
        nonce: str = None,
        name: str = None,
        version: str = None,
        requested_attributes: Mapping = None,
        requested_predicates: Mapping = None,
        non_revoked: Mapping = None,
        **kwargs,
    ):
        """
        Initialize indy cred abstract object.

        Args:
            schema_id: schema identifier
            cred_def_id: credential definition identifier
            nonce: nonce
            key_correctness_proof: key correctness proof

        """
        super().__init__(**kwargs)
        self.nonce = nonce
        self.name = name
        self.version = version
        self.requested_attributes = requested_attributes
        self.requested_predicates = requested_predicates
        self.non_revoked = non_revoked


class IndyProofRequestSchema(BaseModelSchema):
    """Schema for indy proof request."""

    class Meta:
        """Indy proof request schema metadata."""

        model_class = IndyProofRequest
        unknown = EXCLUDE

    nonce = fields.Str(
        description="Nonce",
        required=False,
        **NUM_STR_NATURAL,
    )
    name = fields.Str(
        description="Proof request name",
        required=False,
        example="Proof request",
        default="Proof request",
    )
    version = fields.Str(
        description="Proof request version",
        required=False,
        default="1.0",
        **INDY_VERSION,
    )
    requested_attributes = fields.Dict(
        description="Requested attribute specifications of proof request",
        keys=fields.Str(decription="Attribute referent", example="0_legalname_uuid"),
        values=fields.Nested(IndyProofReqAttrSpecSchema()),
    )
    requested_predicates = fields.Dict(
        description="Requested predicate specifications of proof request",
        keys=fields.Str(description="Predicate referent", example="0_age_GE_uuid"),
        values=fields.Nested(IndyProofReqPredSpecSchema()),
    )
    non_revoked = fields.Nested(
        Schema.from_dict(
            {
                "from": fields.Int(
                    required=False,
                    description="Earliest time of interest in non-revocation interval",
                    strict=True,
                    **INT_EPOCH,
                ),
                "to": fields.Int(
                    required=False,
                    description="Latest time of interest in non-revocation interval",
                    strict=True,
                    **INT_EPOCH,
                ),
            }
        ),
        allow_none=True,  # accommodate libvcx
        required=False,
    )
