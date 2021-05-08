"""Cred request artifacts to attach to RFC 453 messages."""

from typing import Mapping

from marshmallow import EXCLUDE, fields

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.valid import INDY_CRED_DEF_ID, INDY_DID, NUM_STR_WHOLE


class IndyCredRequest(BaseModel):
    """Indy credential request."""

    class Meta:
        """Indy credential request metadata."""

        schema_class = "IndyCredRequestSchema"

    def __init__(
        self,
        prover_did: str = None,
        cred_def_id: str = None,
        blinded_ms: Mapping = None,
        blinded_ms_correctness_proof: Mapping = None,
        nonce: str = None,
        **kwargs,
    ):
        """Initialize indy credential request."""
        super().__init__(**kwargs)
        self.prover_did = prover_did
        self.cred_def_id = cred_def_id
        self.blinded_ms = blinded_ms
        self.blinded_ms_correctness_proof = blinded_ms_correctness_proof
        self.nonce = nonce


class IndyCredRequestSchema(BaseModelSchema):
    """Indy credential request schema."""

    class Meta:
        """Indy credential request schema metadata."""

        model_class = IndyCredRequest
        unknown = EXCLUDE

    prover_did = fields.Str(
        requred=True,
        description="Prover DID",
        **INDY_DID,
    )
    cred_def_id = fields.Str(
        required=True,
        description="Credential definition identifier",
        **INDY_CRED_DEF_ID,
    )
    blinded_ms = fields.Dict(
        required=True,
        description="Blinded master secret",
    )
    blinded_ms_correctness_proof = fields.Dict(
        required=True,
        description="Blinded master secret correctness proof",
    )
    nonce = fields.Str(
        required=True,
        description="Nonce in credential request",
        **NUM_STR_WHOLE,
    )
