"""Linked data proof verifiable options detail artifacts to attach to RFC 453 messages."""

from typing import Optional, Union

from marshmallow import fields, INCLUDE

from .......vc.vc_ld import CredentialSchema
from .......messaging.models.base import BaseModel, BaseModelSchema
from .......vc.vc_ld.models.credential import VerifiableCredential

from .cred_detail_options import LDProofVCDetailOptionsSchema, LDProofVCDetailOptions


class LDProofVCDetail(BaseModel):
    """Linked data proof verifiable credential detail."""

    class Meta:
        """LDProofVCDetail metadata."""

        schema_class = "LDProofVCDetailSchema"

    def __init__(
        self,
        credential: Optional[Union[dict, VerifiableCredential]],
        options: Optional[Union[dict, LDProofVCDetailOptions]],
    ) -> None:
        """Initialize the LDProofVCDetail instance."""
        self.credential = credential
        self.options = options

    def __eq__(self, other: object) -> bool:
        """Comparison between linked data vc details."""
        if isinstance(other, LDProofVCDetail):
            return self.credential == other.credential and self.options == other.options
        return False


class LDProofVCDetailSchema(BaseModelSchema):
    """Linked data proof verifiable credential detail schema."""

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = LDProofVCDetail

    credential = fields.Nested(
        CredentialSchema(),
        required=True,
        description="Detail of the JSON-LD Credential to be issued",
        example={
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/citizenship/v1",
            ],
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": "did:key:z6MkmjY8GnV5i9YTDtPETC2uUAW6ejw3nk5mXF5yci5ab7th",
            "identifier": "83627465",
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2019-12-03T12:19:52Z",
            "credentialSubject": {
                "type": ["PermanentResident", "Person"],
                "givenName": "JOHN",
                "familyName": "SMITH",
                "gender": "Male",
            },
        },
    )

    options = fields.Nested(
        LDProofVCDetailOptionsSchema(),
        required=True,
        description="Options for specifying how the linked data proof is created.",
        example={"proofType": "Ed25519Signature2018"},
    )
