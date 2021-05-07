"""DIF Proof Request Schema"""
from marshmallow import fields, validate, validates_schema, ValidationError
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import UUID4
from ....vc.vc_ld.models import LinkedDataProofSchema

from .pres_exch import PresentationSubmissionSchema, StrOrDictField

class DIFPresSpecSchema(OpenAPISchema):
    """Schema for DIF presentation."""

    id = fields.Str(
        description="ID",
        required=False,
        **UUID4,
        data_key="id",
    )
    contexts = fields.List(
        StrOrDictField(),
        data_key="@context",
    )
    types = fields.List(
        fields.Str(description="Types", required=False),
        data_key="type",
    )
    credentials = fields.List(
        fields.Dict(description="Credentials", required=False),
        data_key="verifiableCredential",
    )
    proof = fields.Nested(
        LinkedDataProofSchema(),
        required=True,
        description="The proof of the credential",
        example={
            "type": "Ed25519Signature2018",
            "verificationMethod": (
                "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyG"
                "o38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
            "created": "2019-12-11T03:50:55",
            "proofPurpose": "assertionMethod",
            "jws": (
                "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0JiNjQiXX0..lKJU0Df"
                "_keblRKhZAS9Qq6zybm-HqUXNVZ8vgEPNTAjQKBhQDxvXNo7nvtUBb_Eq1Ch6YBKY5qBQ"
            ),
        },
        data_key="proof",
    )
    presentation_submission = fields.Nested(
        PresentationSubmissionSchema(), data_key="presentation_submission"
    )