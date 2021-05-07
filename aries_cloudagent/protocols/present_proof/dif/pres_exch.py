"""Schemas for dif presentation exchange attachment."""
from marshmallow import (
    fields,
    validate,
    EXCLUDE,
    INCLUDE,
    pre_load,
    post_dump,
    ValidationError,
)
from typing import Sequence, Union

from ....messaging.models.base import BaseModelSchema, BaseModel
from ....messaging.valid import (
    UUID4,
)
from ....vc.vc_ld.models import LinkedDataProofSchema


class ClaimFormat(BaseModel):
    """Defines Claim field."""

    class Meta:
        """ClaimFormat metadata."""

        schema_class = "ClaimFormatSchema"

    def __init__(
        self,
        *,
        jwt_format_data: Sequence[str] = None,
        jwt_vc_format_data: Sequence[str] = None,
        jwt_vp_format_data: Sequence[str] = None,
        ldp_format_data: Sequence[str] = None,
        ldp_vc_format_data: Sequence[str] = None,
        ldp_vp_format_data: Sequence[str] = None,
    ):
        """Initialize format."""
        self.jwt_format_data = jwt_format_data
        self.jwt_vc_format_data = jwt_vc_format_data
        self.jwt_vp_format_data = jwt_vp_format_data
        self.ldp_format_data = ldp_format_data
        self.ldp_vc_format_data = ldp_vc_format_data
        self.ldp_vp_format_data = ldp_vp_format_data


class ClaimFormatSchema(BaseModelSchema):
    """Single ClaimFormat Schema."""

    class Meta:
        """ClaimFormatSchema metadata."""

        model_class = ClaimFormat
        unknown = EXCLUDE

    jwt_format_data = fields.List(
        fields.Str(required=False),
        required=False,
        data_key="jwt",
    )
    jwt_vc_format_data = fields.List(
        fields.Str(required=False),
        required=False,
        data_key="jwt_vc",
    )
    jwt_vp_format_data = fields.List(
        fields.Str(required=False),
        required=False,
        data_key="jwt_vp",
    )
    ldp_format_data = fields.List(
        fields.Str(required=False),
        required=False,
        data_key="ldp",
    )
    ldp_vc_format_data = fields.List(
        fields.Str(required=False),
        required=False,
        data_key="ldp_vc",
    )
    ldp_vp_format_data = fields.List(
        fields.Str(required=False),
        required=False,
        data_key="ldp_vp",
    )

    @pre_load
    def extract_format_info(self, data, **kwargs):
        """Support deserialization from format dict in pd (DIF spec)."""
        if "jwt" in data:
            data["jwt"] = data["jwt"].pop("alg")
        if "jwt_vc" in data:
            data["jwt_vc"] = data["jwt_vc"].pop("alg")
        if "jwt_vp" in data:
            data["jwt_vp"] = data["jwt_vp"].pop("alg")
        if "ldp" in data:
            data["ldp"] = data["ldp"].pop("proof_type")
        if "ldp_vc" in data:
            data["ldp_vc"] = data["ldp_vc"].pop("proof_type")
        if "ldp_vp" in data:
            data["ldp_vp"] = data["ldp_vp"].pop("proof_type")
        return data

    @post_dump
    def serialize_reformat(self, data, **kwargs):
        """Support serialization to format dict (DIF spec)."""
        new_data = {}
        if "jwt" in data:
            new_data["jwt"] = {"alg": data.get("jwt")}
        if "jwt_vc" in data:
            new_data["jwt_vc"] = {"alg": data.get("jwt_vc")}
        if "jwt_vp" in data:
            new_data["jwt_vp"] = {"alg": data.get("jwt_vp")}
        if "ldp" in data:
            new_data["ldp"] = {"proof_type": data.get("ldp")}
        if "ldp_vc" in data:
            new_data["ldp_vc"] = {"proof_type": data.get("ldp_vc")}
        if "ldp_vp" in data:
            new_data["ldp_vp"] = {"proof_type": data.get("ldp_vp")}
        return new_data


class SubmissionRequirements(BaseModel):
    """describes input to be submitted via a presentation submission."""

    class Meta:
        """SubmissionRequirements metadata."""

        schema_class = "SubmissionRequirementsSchema"

    def __init__(
        self,
        *,
        _name: str = None,
        purpose: str = None,
        rule: str = None,
        count: int = None,
        minimum: int = None,
        maximum: int = None,
        _from: str = None,
        # Self_reference
        from_nested: Sequence = None,
    ):
        """Initialize SubmissionRequirement."""
        self._name = _name
        self.purpose = purpose
        self.rule = rule
        self.count = count
        self.minimum = minimum
        self.maximum = maximum
        self._from = _from
        self.from_nested = from_nested


class SubmissionRequirementsSchema(BaseModelSchema):
    """Single Presentation Definition Schema."""

    class Meta:
        """SubmissionRequirementsSchema metadata."""

        model_class = SubmissionRequirements
        unknown = EXCLUDE

    _name = fields.Str(description="Name", required=False, data_key="name")
    purpose = fields.Str(description="Purpose", required=False, data_key="purpose")
    rule = fields.Str(
        description="Selection",
        required=False,
        validate=validate.OneOf(["all", "pick"]),
        data_key="rule",
    )
    count = fields.Int(
        description="Count Value",
        example=1234,
        required=False,
        strict=True,
        data_key="count",
    )
    minimum = fields.Int(
        description="Min Value",
        example=1234,
        required=False,
        strict=True,
        data_key="min",
    )
    maximum = fields.Int(
        description="Max Value",
        example=1234,
        required=False,
        strict=True,
        data_key="max",
    )
    _from = fields.Str(description="From", required=False, data_key="from")
    # Self References
    from_nested = fields.List(
        fields.Nested(lambda: SubmissionRequirementsSchema(exclude=("from_nested",))),
        required=False,
        data_key="from_nested",
    )

    @pre_load
    def validate_from(self, data, **kwargs):
        """Support validation of from and from_nested."""
        if "from" in data and "from_nested" in data:
            raise ValidationError(
                "Both from and from_nested cannot be "
                "specified in the submission requirement"
            )
        if "from" not in data and "from_nested" not in data:
            raise ValidationError(
                "Either from or from_nested needs to be "
                "specified in the submission requirement"
            )
        return data


class SchemaInputDescriptor(BaseModel):
    """SchemaInputDescriptor."""

    class Meta:
        """SchemaInputDescriptor metadata."""

        schema_class = "SchemaInputDescriptorSchema"

    def __init__(
        self,
        *,
        uri: str = None,
        required: bool = False,
    ):
        """Initialize InputDescriptors."""
        self.uri = uri
        self.required = required


class SchemaInputDescriptorSchema(BaseModelSchema):
    """Single SchemaField Schema."""

    class Meta:
        """SchemaInputDescriptorSchema metadata."""

        model_class = SchemaInputDescriptor
        unknown = EXCLUDE

    uri = fields.Str(
        description="URI",
        required=False,
        data_key="uri",
    )
    required = fields.Bool(description="Required", required=False, data_key="required")


class Holder(BaseModel):
    """Single Holder object for Constraints."""

    class Meta:
        """Holder metadata."""

        schema_class = "HolderSchema"

    def __init__(
        self,
        *,
        field_ids: Sequence[str] = None,
        directive: str = None,
    ):
        """Initialize Holder."""
        self.field_ids = field_ids
        self.directive = directive


class HolderSchema(BaseModelSchema):
    """Single Holder Schema."""

    class Meta:
        """HolderSchema metadata."""

        model_class = Holder
        unknown = EXCLUDE

    field_ids = fields.List(
        fields.Str(
            description="FieldID",
            required=False,
            **UUID4,
        ),
        required=False,
        data_key="field_id",
    )
    directive = fields.Str(
        description="Preference",
        required=False,
        validate=validate.OneOf(["required", "preferred"]),
        data_key="directive",
    )


# Union of str or int or float
class StrOrNumberField(fields.Field):
    """Custom Marshmallow field - union of str, int and float."""

    def _deserialize(self, value, attr, data, **kwargs):
        """Return value if type is str, float or int else raise ValidationError."""
        if isinstance(value, str) or isinstance(value, float) or isinstance(value, int):
            return value
        else:
            raise ValidationError("Field should be str or int or float")


class Filter(BaseModel):
    """Single Filter for the Constraint object."""

    class Meta:
        """Filter metadata."""

        schema_class = "FilterSchema"

    def __init__(
        self,
        *,
        _not: bool = False,
        _type: str = None,
        fmt: str = None,
        pattern: str = None,
        minimum: str = None,
        maximum: str = None,
        min_length: int = None,
        max_length: int = None,
        exclusive_min: str = None,
        exclusive_max: str = None,
        const: str = None,
        enums: Sequence[str] = None,
    ):
        """Initialize Filter."""
        self._type = _type
        self.fmt = fmt
        self.pattern = pattern
        self.minimum = minimum
        self.maximum = maximum
        self.min_length = min_length
        self.max_length = max_length
        self.exclusive_min = exclusive_min
        self.exclusive_max = exclusive_max
        self.const = const
        self.enums = enums
        self._not = _not


class FilterSchema(BaseModelSchema):
    """Single Filter Schema."""

    class Meta:
        """FilterSchema metadata."""

        model_class = Filter
        unknown = EXCLUDE

    _type = fields.Str(description="Type", required=False, data_key="type")
    fmt = fields.Str(
        description="Format",
        required=False,
        data_key="format",
    )
    pattern = fields.Str(
        description="Pattern",
        required=False,
        data_key="pattern",
    )
    minimum = StrOrNumberField(
        description="Minimum",
        required=False,
        data_key="minimum",
    )
    maximum = StrOrNumberField(
        description="Maximum",
        required=False,
        data_key="maximum",
    )
    min_length = fields.Int(
        description="Min Length",
        example=1234,
        strict=True,
        required=False,
        data_key="minLength",
    )
    max_length = fields.Int(
        description="Max Length",
        example=1234,
        strict=True,
        required=False,
        data_key="maxLength",
    )
    exclusive_min = StrOrNumberField(
        description="ExclusiveMinimum",
        required=False,
        data_key="exclusiveMinimum",
    )
    exclusive_max = StrOrNumberField(
        description="ExclusiveMaximum",
        required=False,
        data_key="exclusiveMaximum",
    )
    const = StrOrNumberField(
        description="Const",
        required=False,
        data_key="const",
    )
    enums = fields.List(
        StrOrNumberField(description="Enum", required=False),
        required=False,
        data_key="enum",
    )
    _not = fields.Boolean(
        description="Not",
        required=False,
        example=False,
        data_key="not",
    )

    @pre_load
    def extract_info(self, data, **kwargs):
        """Enum validation and not filter logic."""
        if "not" in data:
            new_data = {"not": True}
            for key, value in data.get("not").items():
                new_data[key] = value
            data = new_data
        if "enum" in data:
            if type(data.get("enum")) is not list:
                raise ValidationError("enum is not specified as a list")
        return data

    @post_dump
    def serialize_reformat(self, data, **kwargs):
        """Support serialization of not filter according to DIF spec."""
        if data.pop("not", False):
            return {"not": data}

        return data


class Field(BaseModel):
    """Single Field object for the Constraint."""

    class Meta:
        """Field metadata."""

        schema_class = "FieldSchema"

    def __init__(
        self,
        *,
        paths: Sequence[str] = None,
        purpose: str = None,
        predicate: str = None,
        _filter: Filter = None,
    ):
        """Initialize Field."""
        self.paths = paths
        self.purpose = purpose
        self.predicate = predicate
        self._filter = _filter


class FieldSchema(BaseModelSchema):
    """Single Field Schema."""

    class Meta:
        """FieldSchema metadata."""

        model_class = Field
        unknown = EXCLUDE

    paths = fields.List(
        fields.Str(description="Path", required=False),
        required=False,
        data_key="path",
    )
    purpose = fields.Str(
        description="Purpose",
        required=False,
        data_key="purpose",
    )
    predicate = fields.Str(
        description="Preference",
        required=False,
        validate=validate.OneOf(["required", "preferred"]),
        data_key="predicate",
    )
    _filter = fields.Nested(FilterSchema, data_key="filter")


class Constraints(BaseModel):
    """Single Constraints which describes InputDescriptor's Contraint field."""

    class Meta:
        """Constraints metadata."""

        schema_class = "ConstraintsSchema"

    def __init__(
        self,
        *,
        subject_issuer: str = None,
        limit_disclosure: bool = None,
        holders: Sequence[Holder] = None,
        _fields: Sequence[Field] = None,
        status_active: str = None,
        status_suspended: str = None,
        status_revoked: str = None,
    ):
        """Initialize Constraints for Input Descriptor."""
        self.subject_issuer = subject_issuer
        self.limit_disclosure = limit_disclosure
        self.holders = holders
        self._fields = _fields
        self.status_active = status_active
        self.status_suspended = status_suspended
        self.status_revoked = status_revoked


class ConstraintsSchema(BaseModelSchema):
    """Single Constraints Schema."""

    class Meta:
        """ConstraintsSchema metadata."""

        model_class = Constraints
        unknown = EXCLUDE

    subject_issuer = fields.Str(
        description="SubjectIsIssuer",
        required=False,
        validate=validate.OneOf(["required", "preferred"]),
        data_key="subject_is_issuer",
    )
    limit_disclosure = fields.Bool(
        description="LimitDisclosure", required=False, data_key="limit_disclosure"
    )
    holders = fields.List(
        fields.Nested(HolderSchema),
        required=False,
        data_key="is_holder",
    )
    _fields = fields.List(
        fields.Nested(FieldSchema),
        required=False,
        data_key="fields",
    )
    status_active = fields.Str(
        required=False,
        validate=validate.OneOf(["required", "allowed", "disallowed"]),
    )
    status_suspended = fields.Str(
        required=False,
        validate=validate.OneOf(["required", "allowed", "disallowed"]),
    )
    status_revoked = fields.Str(
        required=False,
        validate=validate.OneOf(["required", "allowed", "disallowed"]),
    )

    @pre_load
    def extract_info(self, data, **kwargs):
        """Support deserialization of statuses according to DIF spec."""
        if "statuses" in data:
            if "active" in data.get("statuses"):
                if "directive" in data.get("statuses").get("active"):
                    data["status_active"] = data["statuses"]["active"]["directive"]
            if "suspended" in data.get("statuses"):
                if "directive" in data.get("statuses").get("suspended"):
                    data["status_suspended"] = data["statuses"]["suspended"][
                        "directive"
                    ]
            if "revoked" in data.get("statuses"):
                if "directive" in data.get("statuses").get("revoked"):
                    data["status_revoked"] = data["statuses"]["revoked"]["directive"]
        if "limit_disclosure" in data:
            if data.get("limit_disclosure") == "required":
                data["limit_disclosure"] = True
            else:
                data["limit_disclosure"] = False
        return data

    @post_dump
    def reformat_data(self, data, **kwargs):
        """Support serialization of statuses according to DIF spec."""
        if "status_active" in data:
            statuses = data.get("statuses", {})
            statuses["active"] = {"directive": data.get("status_active")}
            data["statuses"] = statuses
            del data["status_active"]
        if "status_suspended" in data:
            statuses = data.get("statuses", {})
            statuses["suspended"] = {"directive": data.get("status_suspended")}
            data["statuses"] = statuses
            del data["status_suspended"]
        if "status_revoked" in data:
            statuses = data.get("statuses", {})
            statuses["revoked"] = {"directive": data.get("status_revoked")}
            data["statuses"] = statuses
            del data["status_revoked"]
        return data


class InputDescriptors(BaseModel):
    """Input Descriptors."""

    class Meta:
        """InputDescriptors metadata."""

        schema_class = "InputDescriptorsSchema"

    def __init__(
        self,
        *,
        id: str = None,
        groups: Sequence[str] = None,
        name: str = None,
        purpose: str = None,
        metadata: dict = None,
        constraint: Constraints = None,
        schemas: Sequence[SchemaInputDescriptor] = None,
    ):
        """Initialize InputDescriptors."""
        self.id = id
        self.groups = groups
        self.name = name
        self.purpose = purpose
        self.metadata = metadata
        self.constraint = constraint
        self.schemas = schemas


class InputDescriptorsSchema(BaseModelSchema):
    """Single InputDescriptors Schema."""

    class Meta:
        """InputDescriptorsSchema metadata."""

        model_class = InputDescriptors
        unknown = EXCLUDE

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


class Requirement(BaseModel):
    """Single Requirement generated from toRequirement function."""

    class Meta:
        """Requirement metadata."""

        schema_class = "RequirementSchema"

    def __init__(
        self,
        *,
        count: int = None,
        maximum: int = None,
        minimum: int = None,
        input_descriptors: Sequence[InputDescriptors] = None,
        nested_req: Sequence = None,
    ):
        """Initialize Requirement."""
        self.count = count
        self.maximum = maximum
        self.minimum = minimum
        self.input_descriptors = input_descriptors
        self.nested_req = nested_req


class RequirementSchema(BaseModelSchema):
    """Single Requirement Schema."""

    class Meta:
        """RequirementSchema metadata."""

        model_class = Requirement
        unknown = EXCLUDE

    count = fields.Int(
        description="Count Value",
        example=1234,
        strict=True,
        required=False,
    )
    maximum = fields.Int(
        description="Max Value",
        example=1234,
        strict=True,
        required=False,
    )
    minimum = fields.Int(
        description="Min Value",
        example=1234,
        strict=True,
        required=False,
    )
    input_descriptors = fields.List(
        fields.Nested(InputDescriptorsSchema),
        required=False,
    )
    # Self References
    nested_req = fields.List(
        fields.Nested(lambda: RequirementSchema(exclude=("_nested_req",))),
        required=False,
    )


class PresentationDefinition(BaseModel):
    """https://identity.foundation/presentation-exchange/."""

    class Meta:
        """PresentationDefinition metadata."""

        schema_class = "PresentationDefinitionSchema"

    def __init__(
        self,
        *,
        id: str = None,
        name: str = None,
        purpose: str = None,
        fmt: ClaimFormat = None,
        submission_requirements: Sequence[SubmissionRequirements] = None,
        input_descriptors: Sequence[InputDescriptors] = None,
        **kwargs,
    ):
        """Initialize flattened single-JWS to include in attach decorator data."""
        super().__init__(**kwargs)
        self.id = id
        self.name = name
        self.purpose = purpose
        self.fmt = fmt
        self.submission_requirements = submission_requirements
        self.input_descriptors = input_descriptors


class PresentationDefinitionSchema(BaseModelSchema):
    """Single Presentation Definition Schema."""

    class Meta:
        """PresentationDefinitionSchema metadata."""

        model_class = PresentationDefinition
        unknown = EXCLUDE

    id = fields.Str(
        required=False,
        description="Unique Resource Identifier",
        **UUID4,
        data_key="id",
    )
    name = fields.Str(
        description=(
            "Human-friendly name that describes"
            " what the presentation definition pertains to"
        ),
        required=False,
        data_key="name",
    )
    purpose = fields.Str(
        description=(
            "Describes the purpose for which"
            " the Presentation Definition's inputs are being requested"
        ),
        required=False,
        data_key="purpose",
    )
    fmt = fields.Nested(
        ClaimFormatSchema,
        required=False,
        data_key="format",
    )
    submission_requirements = fields.List(
        fields.Nested(SubmissionRequirementsSchema),
        required=False,
        data_key="submission_requirements",
    )
    input_descriptors = fields.List(
        fields.Nested(InputDescriptorsSchema),
        required=False,
        data_key="input_descriptors",
    )


class InputDescriptorMapping(BaseModel):
    """Single InputDescriptorMapping object."""

    class Meta:
        """InputDescriptorMapping metadata."""

        schema_class = "InputDescriptorMappingSchema"

    def __init__(
        self,
        *,
        id: str = None,
        fmt: str = None,
        path: str = None,
    ):
        """Initialize InputDescriptorMapping."""
        self.id = id
        self.fmt = fmt
        self.path = path


class InputDescriptorMappingSchema(BaseModelSchema):
    """Single InputDescriptorMapping Schema."""

    class Meta:
        """InputDescriptorMappingSchema metadata."""

        model_class = InputDescriptorMapping
        unknown = EXCLUDE

    id = fields.Str(
        description="ID",
        required=False,
        data_key="id",
    )
    fmt = fields.Str(
        description="Format",
        required=False,
        default="ldp_vp",
        data_key="format",
    )
    path = fields.Str(
        description="Path",
        required=False,
        data_key="path",
    )


class PresentationSubmission(BaseModel):
    """Single PresentationSubmission object."""

    class Meta:
        """PresentationSubmission metadata."""

        schema_class = "PresentationSubmissionSchema"

    def __init__(
        self,
        *,
        id: str = None,
        definition_id: str = None,
        descriptor_maps: Sequence[InputDescriptorMapping] = None,
    ):
        """Initialize InputDescriptorMapping."""
        self.id = id
        self.definition_id = definition_id
        self.descriptor_maps = descriptor_maps


class PresentationSubmissionSchema(BaseModelSchema):
    """Single PresentationSubmission Schema."""

    class Meta:
        """PresentationSubmissionSchema metadata."""

        model_class = PresentationSubmission
        unknown = EXCLUDE

    id = fields.Str(
        description="ID",
        required=False,
        **UUID4,
        data_key="id",
    )
    definition_id = fields.Str(
        description="DefinitionID",
        required=False,
        **UUID4,
        data_key="definition_id",
    )
    descriptor_maps = fields.List(
        fields.Nested(InputDescriptorMappingSchema),
        required=False,
        data_key="descriptor_map",
    )


# Union of str or dict
class StrOrDictField(fields.Field):
    """Custom Marshmallow field - union of str and dict."""

    def _deserialize(self, value, attr, data, **kwargs):
        """Return value if type is str or dict else raise ValidationError."""
        if isinstance(value, str) or isinstance(value, dict):
            return value
        else:
            raise ValidationError("Field should be str or dict")


# class VerifiablePresentation(BaseModel):
#     """Single VerifiablePresentation object."""

#     class Meta:
#         """VerifiablePresentation metadata."""

#         schema_class = "VerifiablePresentationSchema"

#     def __init__(
#         self,
#         *,
#         id: str = None,
#         contexts: Sequence[Union[str, dict]] = None,
#         types: Sequence[str] = None,
#         credentials: Sequence[dict] = None,
#         proof: Sequence[dict] = None,
#         presentation_submission: PresentationSubmission = None,
#     ):
#         """Initialize VerifiablePresentation."""
#         self.id = id
#         self.contexts = contexts
#         self.types = types
#         self.credentials = credentials
#         self.proof = proof
#         self.presentation_submission = presentation_submission


# class VerifiablePresentationSchema(BaseModelSchema):
#     """Single Field Schema."""

#     class Meta:
#         """VerifiablePresentationSchema metadata."""

#         model_class = VerifiablePresentation
#         unknown = INCLUDE

#     id = fields.Str(
#         description="ID",
#         required=False,
#         **UUID4,
#         data_key="id",
#     )
#     contexts = fields.List(
#         StrOrDictField(),
#         data_key="@context",
#     )
#     types = fields.List(
#         fields.Str(description="Types", required=False),
#         data_key="type",
#     )
#     credentials = fields.List(
#         fields.Dict(description="Credentials", required=False),
#         data_key="verifiableCredential",
#     )
#     proof = fields.Nested(
#         LinkedDataProofSchema(),
#         required=True,
#         description="The proof of the credential",
#         example={
#             "type": "Ed25519Signature2018",
#             "verificationMethod": (
#                 "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyG"
#                 "o38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
#             ),
#             "created": "2019-12-11T03:50:55",
#             "proofPurpose": "assertionMethod",
#             "jws": (
#                 "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0JiNjQiXX0..lKJU0Df"
#                 "_keblRKhZAS9Qq6zybm-HqUXNVZ8vgEPNTAjQKBhQDxvXNo7nvtUBb_Eq1Ch6YBKY5qBQ"
#             ),
#         },
#         data_key="proof",
#     )
#     presentation_submission = fields.Nested(
#         PresentationSubmissionSchema, data_key="presentation_submission"
#     )
