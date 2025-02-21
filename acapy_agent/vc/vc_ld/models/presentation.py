"""Verifiable Presentation model."""

from typing import List, Optional, Union

from marshmallow import INCLUDE, ValidationError, fields, post_dump

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.valid import (
    CREDENTIAL_CONTEXT_VALIDATE,
    PRESENTATION_TYPE_EXAMPLE,
    PRESENTATION_TYPE_VALIDATE,
    DIDKey,
    StrOrDictField,
    Uri,
    UriOrDictField,
)
from ...ld_proofs.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
    VERIFIABLE_PRESENTATION_TYPE,
)
from .linked_data_proof import LDProof, LinkedDataProofSchema


class VerifiablePresentation(BaseModel):
    """Single VerifiablePresentation object."""

    class Meta:
        """VerifiablePresentation metadata."""

        schema_class = "PresentationSchema"

    def __init__(
        self,
        context: Optional[List[Union[str, dict]]] = None,
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        holder: Optional[Union[dict, str]] = None,
        verifiable_credential: Optional[List[dict]] = None,
        proof: Optional[Union[dict, LDProof]] = None,
        **kwargs,
    ) -> None:
        """Initialize VerifiablePresentation."""
        self._context = context or [CREDENTIALS_CONTEXT_V1_URL]
        self._id = id
        self._holder = holder
        self._type = type or [VERIFIABLE_PRESENTATION_TYPE]
        self._verifiable_credential = verifiable_credential

        self._proof = proof

        self.extra = kwargs

    @property
    def context(self):
        """Getter for context."""
        return self._context

    @context.setter
    def context(self, context: List[Union[str, dict]]):
        """Setter for context.

        First item must be credentials v1 url
        """
        assert context[0] in [CREDENTIALS_CONTEXT_V1_URL, CREDENTIALS_CONTEXT_V2_URL]

        self._context = context

    def add_context(self, context: Union[str, dict]):
        """Add a context to this presentation."""
        self._context.append(context)

    @property
    def context_urls(self) -> List[str]:
        """Getter for context urls."""
        return [context for context in self.context if isinstance(context, str)]

    @property
    def type(self) -> List[str]:
        """Getter for type."""
        return self._type

    @type.setter
    def type(self, type: List[str]):
        """Setter for type.

        First item must be VerifiablePresentation
        """
        assert VERIFIABLE_PRESENTATION_TYPE in type

        self._type = type

    def add_type(self, type: str):
        """Add a type to this presentation."""
        self._type.append(type)

    @property
    def id(self):
        """Getter for id."""
        return self._id

    @id.setter
    def id(self, id: Union[str, None]):
        """Setter for id."""
        if id:
            uri_validator = Uri()
            uri_validator(id)

        self._id = id

    @property
    def holder_id(self) -> Optional[str]:
        """Getter for holder id."""
        if not self._holder:
            return None
        elif isinstance(self._holder, str):
            return self._holder

        return self._holder.get("id")

    @holder_id.setter
    def holder_id(self, holder_id: str):
        """Setter for holder id."""
        uri_validator = Uri()
        uri_validator(holder_id)

        # Use simple string variant if possible
        if not self._holder or isinstance(self._holder, str):
            self._holder = holder_id
        else:
            self._holder["id"] = holder_id

    @property
    def holder(self):
        """Getter for holder."""
        return self._holder

    @holder.setter
    def holder(self, holder: Union[str, dict]):
        """Setter for holder."""
        uri_validator = Uri()

        holder_id = holder if isinstance(holder, str) else holder.get("id")

        if not holder_id:
            raise ValidationError("Holder id is required")
        uri_validator(holder_id)

        self._holder = holder

    @property
    def verifiable_credential(self):
        """Getter for verifiable credential."""
        return self._verifiable_credential

    @verifiable_credential.setter
    def verifiable_credential(self, verifiable_credential: List[dict]):
        """Setter for verifiable credential."""

        self._verifiable_credential = verifiable_credential

    @property
    def proof(self):
        """Getter for proof."""
        return self._proof

    @proof.setter
    def proof(self, proof: LDProof):
        """Setter for proof."""
        self._proof = proof

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, VerifiablePresentation):
            return (
                self.context == o.context
                and self.id == o.id
                and self.type == o.type
                and self.holder == o.holder
                and self.verifiable_credentials == o.verifiable_credentials
                and self.proof == o.proof
                and self.extra == o.extra
            )

        return False


class PresentationSchema(BaseModelSchema):
    """Linked data presentation schema.

    Based on https://www.w3.org/TR/vc-data-model

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = VerifiablePresentation

    context = fields.List(
        UriOrDictField(required=True),
        data_key="@context",
        required=True,
        validate=CREDENTIAL_CONTEXT_VALIDATE,
        metadata={
            "description": "The JSON-LD context of the presentation",
            "example": [CREDENTIALS_CONTEXT_V1_URL],
        },
    )

    id = fields.Str(
        required=False,
        validate=Uri(),
        metadata={
            "description": "The ID of the presentation",
            "example": "http://example.edu/presentations/1872",
        },
    )

    type = fields.List(
        fields.Str(required=True),
        required=True,
        validate=PRESENTATION_TYPE_VALIDATE,
        metadata={
            "description": "The JSON-LD type of the presentation",
            "example": PRESENTATION_TYPE_EXAMPLE,
        },
    )

    holder = StrOrDictField(
        required=False,
        metadata={
            "description": (
                "The JSON-LD Verifiable Credential Holder. Either string of object with"
                " id field."
            ),
            "example": DIDKey.EXAMPLE,
        },
    )

    # TODO how to validate VCs in list
    verifiable_credential = fields.List(
        fields.Dict(required=True),
        required=False,
        data_key="verifiableCredential",
        metadata={},
    )

    proof = fields.Nested(
        LinkedDataProofSchema(),
        required=False,
        metadata={
            "description": "The proof of the presentation",
            "example": {
                "type": "Ed25519Signature2018",
                "verificationMethod": (
                    "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38Ee"
                    "fXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                ),
                "created": "2019-12-11T03:50:55",
                "proofPurpose": "assertionMethod",
                "jws": (
                    "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0JiNjQiXX0..lKJU0Df_k"
                    "eblRKhZAS9Qq6zybm-HqUXNVZ8vgEPNTAjQKBhQDxvXNo7nvtUBb_Eq1Ch6YBKY5qBQ"
                ),
            },
        },
    )

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data


class VerifiablePresentationSchema(PresentationSchema):
    """Single Verifiable Presentation Schema."""

    proof = fields.Nested(
        LinkedDataProofSchema(),
        required=True,
        metadata={
            "description": "The proof of the presentation",
            "example": {
                "type": "Ed25519Signature2018",
                "verificationMethod": (
                    "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38Ee"
                    "fXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
                ),
                "created": "2019-12-11T03:50:55",
                "proofPurpose": "assertionMethod",
                "jws": (
                    "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0JiNjQiXX0..lKJU0Df_k"
                    "eblRKhZAS9Qq6zybm-HqUXNVZ8vgEPNTAjQKBhQDxvXNo7nvtUBb_Eq1Ch6YBKY5qBQ"
                ),
            },
        },
    )
