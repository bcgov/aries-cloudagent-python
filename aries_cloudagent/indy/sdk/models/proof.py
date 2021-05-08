"""Marshmallow bindings for indy proofs."""

from typing import Mapping, Sequence

from marshmallow import EXCLUDE, fields, validate

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.valid import (
    INDY_CRED_DEF_ID,
    INDY_REV_REG_ID,
    INDY_SCHEMA_ID,
    INT_EPOCH,
    NUM_STR_WHOLE,
)
from ....utils.tracing import AdminAPIMessageTracingSchema

from .predicate import Predicate
from .requested_creds import (
    IndyRequestedCredsRequestedAttrSchema,
    IndyRequestedCredsRequestedPredSchema,
)


class IndyEQProof(BaseModel):
    """Equality proof for indy primary proof."""

    class Meta:
        """Equality proof metadata."""

        schema_class = "IndyEQProofMeta"

    def __init__(
        self,
        revealed_attrs: Mapping[str, str] = None,
        a_prime: str = None,
        e: str = None,
        v: str = None,
        m: Mapping[str, str] = None,
        m2: str = None,
        **kwargs,
    ):
        """Initialize equality proof object."""
        super().__init__(**kwargs)
        self.revealed_attrs = revealed_attrs
        self.a_prime = a_prime
        self.e = e
        self.v = v
        self.m = m
        self.m2 = m2


class IndyEQProofSchema(BaseModelSchema):
    """Indy equality proof schema."""

    class Meta:
        """Indy equality proof metadata."""

        model_class = IndyEQProof
        unknown = EXCLUDE

    revealed_attrs = fields.Dict(
        keys=fields.Str(example="preference"),
        values=fields.Str(**NUM_STR_WHOLE),
    )
    a_prime = fields.Str(**NUM_STR_WHOLE)
    e = fields.Str(**NUM_STR_WHOLE)
    v = fields.Str(**NUM_STR_WHOLE)
    m = fields.Dict(
        keys=fields.Str(example="master_secret"),
        values=fields.Str(**NUM_STR_WHOLE),
    )
    m2 = fields.Str(**NUM_STR_WHOLE)


class IndyGEProofPred(BaseModel):
    """Indy GE proof predicate."""

    class Meta:
        """Indy GE proof predicate metadata."""

        schema_class = "IndyGEProofPredSchema"

    def __init__(
        self,
        attr_name: str = None,
        p_type: str = None,
        value: int = None,
        **kwargs,
    ):
        """Initialize indy GE proof predicate."""
        super().__init__(**kwargs)
        self.attr_name = attr_name
        self.p_type = p_type
        self.value = value


class IndyGEProofPredSchema(BaseModelSchema):
    """Indy GE proof predicate schema."""

    class Meta:
        """Indy GE proof predicate metadata."""

        model_class = IndyGEProofPred
        unknown = EXCLUDE

    attr_name = fields.Str(description="Attribute name, indy-canonicalized")
    p_type = fields.Str(
        description="Predicate type",
        validate=validate.OneOf([p.fortran for p in Predicate]),
    )
    value = fields.Integer(strict=True, description="Predicate threshold value")


class IndyGEProof(BaseModel):
    """Greater-than-or-equal-to proof for indy primary proof."""

    class Meta:
        """GE proof metadata."""

        schema_class = "IndyGEProofMeta"

    def __init__(
        self,
        u: Mapping[str, str] = None,
        r: Mapping[str, str] = None,
        mj: str = None,
        alpha: str = None,
        t: Mapping[str, str] = None,
        predicate: IndyGEProofPred = None,
        **kwargs,
    ):
        """Initialize GE proof object."""
        super().__init__(**kwargs)
        self.u = u
        self.r = r
        self.mj = mj
        self.alpha = alpha
        self.t = t
        self.predicate = predicate


class IndyGEProofSchema(BaseModelSchema):
    """Indy GE proof schema."""

    class Meta:
        """Indy GE proof schema metadata."""

        model_class = IndyGEProof
        unknown = EXCLUDE

    u = fields.Dict(keys=fields.Str(), values=fields.Str(**NUM_STR_WHOLE))
    r = fields.Dict(keys=fields.Str(), values=fields.Str(**NUM_STR_WHOLE))
    mj = fields.Str(**NUM_STR_WHOLE)
    alpha = fields.Str(**NUM_STR_WHOLE)
    t = fields.Dict(keys=fields.Str(), values=fields.Str(**NUM_STR_WHOLE))
    predicate = fields.Nested(IndyGEProofPredSchema)


class IndyPrimaryProof(BaseModel):
    """Indy primary proof."""

    class Meta:
        """Indy primary proof metadata."""

        schema_class = "IndyPrimaryProofSchema"

    def __init__(
        self,
        eq_proof: IndyEQProof = None,
        ge_proofs: Sequence[IndyGEProof] = None,
        **kwargs,
    ):
        """Initialize indy primary proof."""
        super().__init__(**kwargs)
        self.eq_proof = eq_proof
        self.ge_proofs = ge_proofs


class IndyPrimaryProofSchema(BaseModelSchema):
    """Indy primary proof schema."""

    class Meta:
        """Indy primary proof schema metadata."""

        model_class = IndyPrimaryProof
        unknown = EXCLUDE

    eq_proof = fields.Nested(
        IndyEQProofSchema, allow_none=True, description="Indy equality proof"
    )
    ge_proofs = fields.Nested(
        IndyGEProofSchema,
        many=True,
        allow_none=True,
        description="Indy GE proofs",
    )


class IndyNonRevocProof(BaseModel):
    """Indy non-revocation proof."""

    class Meta:
        """Indy non-revocation proof metadata."""

        schema_class = "IndyNonRevocProofSchema"

    def __init__(
        self,
        x_list: Mapping = None,
        c_list: Mapping = None,
        **kwargs,
    ):
        """Initialize indy non-revocation proof."""
        super().__init__(**kwargs)
        self.x_list = x_list
        self.c_list = c_list


class IndyNonRevocProofSchema(BaseModelSchema):
    """Indy non-revocation proof schema."""

    class Meta:
        """Indy non-revocation proof schema metadata."""

        model_class = IndyNonRevocProof
        unknown = EXCLUDE

    x_list = fields.Dict(keys=fields.Str(), values=fields.Str())
    c_list = fields.Dict(keys=fields.Str(), values=fields.Str())


class IndyProofProofProofsProof(BaseModel):
    """Indy proof.proof.proofs constituent proof."""

    class Meta:
        """Indy proof.proof.proofs constituent proof schema."""

        schema_class = "IndyProofProofProofsProofSchema"

    def __init__(
        self,
        primary_proof: IndyPrimaryProof = None,
        non_revoc_proof: IndyNonRevocProof = None,
        **kwargs,
    ):
        """Initialize proof.proof.proofs constituent proof."""
        super().__init__(**kwargs)
        self.primary_proof = primary_proof
        self.non_revoc_proof = non_revoc_proof


class IndyProofProofProofsProofSchema(BaseModelSchema):
    """Indy proof.proof.proofs constituent proof schema."""

    class Meta:
        """Indy proof.proof.proofs constituent proof schema metadata."""

        model_class = IndyProofProofProofsProof
        unknown = EXCLUDE

    primary_proof = fields.Nested(
        IndyPrimaryProofSchema,
        description="Indy primary proof",
    )
    non_revoc_proof = fields.Nested(
        IndyNonRevocProofSchema,
        allow_none=True,
        description="Indy non-revocation proof",
    )


class IndyProofProofAggregatedProof(BaseModel):
    """Indy proof.proof aggregated proof."""

    class Meta:
        """Indy proof.proof aggregated proof metadata."""

        schema_class = "IndyProofProofAggregatedProofSchema"

    def __init__(
        self,
        c_hash: str = None,
        c_list: Sequence[Sequence[int]] = None,
        **kwargs,
    ):
        """Initialize indy proof.proof agreggated proof."""
        super().__init__(**kwargs)
        self.c_hash = c_hash
        self.c_list = c_list


class IndyProofProofAggregatedProofSchema(BaseModelSchema):
    """Indy proof.proof aggregated proof schema."""

    class Meta:
        """Indy proof.proof aggregated proof schema metadata."""

        model_class = IndyProofProofAggregatedProof
        unknown = EXCLUDE

    c_hash = fields.Str(description="c_hash value")
    c_list = fields.List(
        fields.List(fields.Int(strict=True)),
        description="c_list value",
    )


class IndyProofProof(BaseModel):
    """Indy proof.proof content."""

    class Meta:
        """Indy proof.proof content metadata."""

        schema_class = "IndyProofProofSchema"

    def __init__(
        self,
        proofs: Sequence[IndyProofProofProofsProof] = None,
        aggregated_proof: IndyProofProofAggregatedProof = None,
        **kwargs,
    ):
        """Initialize indy proof.proof content."""
        super().__init__(**kwargs)
        self.proofs = proofs
        self.aggregated_proof = aggregated_proof


class IndyProofProofSchema(BaseModelSchema):
    """Indy proof.proof content schema."""

    class Meta:
        """Indy proof.proof content schema metadata."""

        model_class = IndyProofProof
        unknown = EXCLUDE

    proofs = fields.Nested(
        IndyProofProofProofsProofSchema,
        many=True,
        description="Indy proof proofs",
    )
    aggregated_proof = fields.Nested(
        IndyProofProofAggregatedProofSchema,
        description="Indy proof aggregated proof",
    )


class RawEncoded(BaseModel):
    """Raw and encoded attribute values."""

    class Meta:
        """Raw and encoded attribute values metadata."""

        schema_class = "RawEncodedSchema"

    def __init__(
        self,
        raw: str = None,
        encoded: str = None,
        **kwargs,
    ):
        """Initialize raw and encoded attribute values."""
        super().__init__(**kwargs)
        self.raw = raw
        self.encoded = encoded


class RawEncodedSchema(BaseModelSchema):
    """Raw and encoded attribute values schema."""

    class Meta:
        """Raw and encoded attribute values schema metadata."""

        model_class = RawEncoded
        unknown = EXCLUDE

    raw = fields.Str(description="Raw value")
    encoded = fields.Str(description="Encoded value", **NUM_STR_WHOLE)


class IndyProofRequestedProofRevealedAttr(RawEncoded):
    """Indy proof requested proof revealed attr."""

    class Meta:
        """Indy proof requested proof revealed attr metadata."""

        schema_class = "IndyProofRequestedProofRevealedAttrSchema"

    def __init__(
        self,
        sub_proof_index: int = None,
        **kwargs,
    ):
        """Initialize indy proof requested proof revealed attr."""
        super().__init__(**kwargs)
        self.sub_proof_index = sub_proof_index


class IndyProofRequestedProofRevealedAttrSchema(RawEncodedSchema):
    """Indy proof requested proof revealed attr schema."""

    class Meta:
        """Indy proof requested proof revealed attr schema metadata."""

        model_class = IndyProofRequestedProofRevealedAttr
        unknown = EXCLUDE

    sub_proof_index = fields.Int(strict=True, description="Sub-proof index")


class IndyProofRequestedProofRevealedAttrGroup(BaseModel):
    """Indy proof requested proof revealed attr group."""

    class Meta:
        """Indy proof requested proof revealed attr group metadata."""

        schema_class = "IndyProofRequestedProofRevealedAttrGroupSchema"

    def __init__(
        self,
        sub_proof_index: int = None,
        values: Mapping[str, RawEncoded] = None,
        **kwargs,
    ):
        """Initialize indy proof requested proof revealed attr."""
        super().__init__(**kwargs)
        self.sub_proof_index = sub_proof_index
        self.values = values


class IndyProofRequestedProofRevealedAttrGroupSchema(BaseModelSchema):
    """Indy proof requested proof revealed attr group schema."""

    class Meta:
        """Indy proof requested proof revealed attr group schema metadata."""

        model_class = IndyProofRequestedProofRevealedAttrGroup
        unknown = EXCLUDE

    sub_proof_index = fields.Int(strict=True, description="Sub-proof index")
    values = fields.Dict(
        keys=fields.Str(),
        values=fields.Nested(RawEncodedSchema),
        description="Indy proof requested proof revealed attr groups group value",
    )


class IndyProofRequestedProofPredicate(BaseModel):
    """Indy proof requested proof predicate."""

    class Meta:
        """Indy proof requested proof requested proof predicate metadata."""

        schema_class = "IndyProofRequestedProofPredicateSchema"

    def __init__(
        self,
        sub_proof_index: int = None,
        **kwargs,
    ):
        """Initialize indy proof requested proof predicate."""
        super().__init__(**kwargs)
        self.sub_proof_index = sub_proof_index


class IndyProofRequestedProofPredicateSchema(BaseModelSchema):
    """Indy proof requested prrof predicate schema."""

    class Meta:
        """Indy proof requested proof requested proof predicate schema metadata."""

        model_class = IndyProofRequestedProofPredicate
        unknown = EXCLUDE

    sub_proof_index = fields.Int(strict=True, description="Sub-proof index")


class IndyProofRequestedProof(BaseModel):
    """Indy proof.requested_proof content."""

    class Meta:
        """Indy proof.requested_proof content metadata."""

        schema_class = "IndyProofRequestedProofSchema"

    def __init__(
        self,
        revealed_attrs: Mapping[str, IndyProofRequestedProofRevealedAttr] = None,
        revealed_attr_groups: Mapping[
            str,
            IndyProofRequestedProofRevealedAttrGroup,
        ] = None,
        self_attested_attrs: Mapping = None,
        unrevealed_attrs: Mapping = None,
        predicates: Mapping[str, IndyProofRequestedProofPredicate] = None,
        **kwargs,
    ):
        """Initialize indy proof requested proof."""
        super().__init__(**kwargs)
        self.revealed_attrs = revealed_attrs
        self.revealed_attr_groups = revealed_attr_groups
        self.self_attested_attrs = self_attested_attrs
        self.unrevealed_attrs = unrevealed_attrs
        self.predicates = predicates


class IndyProofRequestedProofSchema(BaseModelSchema):
    """Indy proof requested proof schema."""

    class Meta:
        """Indy proof requested proof schema metadata."""

        model_class = IndyProofRequestedProof
        unknown = EXCLUDE

    revealed_attrs = fields.Dict(
        keys=fields.Str(),
        values=fields.Nested(IndyProofRequestedProofRevealedAttrSchema),
        allow_none=True,
        description="Proof requested proof revealed attributes",
    )
    revealed_attr_groups = fields.Dict(
        keys=fields.Str(),
        values=fields.Nested(IndyProofRequestedProofRevealedAttrGroupSchema),
        allow_none=True,
        description="Proof requested proof revealed attribute groups",
    )
    self_attested_attrs = fields.Dict(
        description="Proof requested proof self-attested attributes"
    )
    unrevealed_attrs = fields.Dict(description="Unrevealed attributes")
    predicates = fields.Dict(
        keys=fields.Str(),
        values=fields.Nested(
            IndyProofRequestedProofPredicateSchema,
        ),
        description="Proof requested proof predicates.",
    )


class IndyProofIdentifier(BaseModel):
    """Indy proof identifier."""

    class Meta:
        """Indy proof identifier metadata."""

        schema_class = "IndyProofIdentifierSchema"

    def __init__(
        self,
        schema_id: str = None,
        cred_def_id: str = None,
        rev_reg_id: str = None,
        timestamp: int = None,
        **kwargs,
    ):
        """Initialize indy proof identifier."""
        super().__init__(**kwargs)
        self.schema_id = schema_id
        self.cred_def_id = cred_def_id
        self.rev_reg_id = rev_reg_id
        self.timestamp = timestamp


class IndyProofIdentifierSchema(BaseModelSchema):
    """Indy proof identifier schema."""

    class Meta:
        """Indy proof identifier schema metadata."""

        model_class = IndyProofIdentifier
        unknown = EXCLUDE

    schema_id = fields.Str(description="Schema identifier", **INDY_SCHEMA_ID)
    cred_def_id = fields.Str(
        description="Credential definition identifier",
        **INDY_CRED_DEF_ID,
    )
    rev_reg_id = fields.Str(
        description="Revocation registry identifier",
        allow_none=True,
        **INDY_REV_REG_ID,
    )
    timestamp = fields.Int(
        strict=True,
        allow_none=True,
        description="Timestamp epoch",
        **INT_EPOCH,
    )


class IndyProof(BaseModel):
    """Indy proof."""

    class Meta:
        """Indy proof metadata."""

        schema_class = "IndyProofSchema"

    def __init__(
        self,
        proof: IndyProofProof = None,
        requested_proof: IndyProofRequestedProof = None,
        identifiers: Sequence[IndyProofIdentifier] = None,
        **kwargs,
    ):
        """Initialize indy proof."""
        super().__init__(**kwargs)
        self.proof = proof
        self.requested_proof = requested_proof
        self.identifiers = identifiers


class IndyProofSchema(BaseModelSchema):
    """Indy proof schema."""

    class Meta:
        """Indy proof schema metadata."""

        model_class = IndyProof
        unknown = EXCLUDE

    proof = fields.Nested(
        IndyProofProofSchema,
        description="Indy proof.proof content",
    )
    requested_proof = fields.Nested(
        IndyProofRequestedProofSchema,
        description="Indy proof.requested_proof content",
    )
    identifiers = fields.Nested(
        IndyProofIdentifierSchema,
        many=True,
        description="Indy proof.identifiers content",
    )


class IndyPresSpecSchema(AdminAPIMessageTracingSchema):
    """Request schema for indy proof specification to send as presentation."""

    self_attested_attributes = fields.Dict(
        description="Self-attested attributes to build into proof",
        required=True,
        keys=fields.Str(example="attr_name"),  # marshmallow/apispec v3.0 ignores
        values=fields.Str(
            example="self_attested_value",
            description=(
                "Self-attested attribute values to use in requested-credentials "
                "structure for proof construction"
            ),
        ),
    )
    requested_attributes = fields.Dict(
        description=(
            "Nested object mapping proof request attribute referents to "
            "requested-attribute specifiers"
        ),
        required=True,
        keys=fields.Str(example="attr_referent"),  # marshmallow/apispec v3.0 ignores
        values=fields.Nested(IndyRequestedCredsRequestedAttrSchema),
    )
    requested_predicates = fields.Dict(
        description=(
            "Nested object mapping proof request predicate referents to "
            "requested-predicate specifiers"
        ),
        required=True,
        keys=fields.Str(example="pred_referent"),  # marshmallow/apispec v3.0 ignores
        values=fields.Nested(IndyRequestedCredsRequestedPredSchema),
    )
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )
