"""Manager for performing Linked Data Proof signatures over JSON-LD formatted W3C VCs."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Type, Union, cast

from pyld import jsonld
from pyld.jsonld import JsonLdProcessor

from acapy_agent.vc.ld_proofs.suites.ecdsa_secp256r1_signature_2019 import (
    EcdsaSecp256r1Signature2019,
)

from ...core.profile import Profile
from ...storage.vc_holder.base import VCHolder
from ...storage.vc_holder.vc_record import VCRecord
from ...wallet.base import BaseWallet
from ...wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ...wallet.did_info import DIDInfo
from ...wallet.error import WalletNotFoundError
from ...wallet.key_type import BLS12381G2, ED25519, P256, KeyType
from ..ld_proofs.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
    SECURITY_CONTEXT_BBS_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
)
from ..ld_proofs.crypto.wallet_key_pair import WalletKeyPair
from ..ld_proofs.document_loader import DocumentLoader
from ..ld_proofs.purposes.authentication_proof_purpose import AuthenticationProofPurpose
from ..ld_proofs.purposes.credential_issuance_purpose import CredentialIssuancePurpose
from ..ld_proofs.purposes.proof_purpose import ProofPurpose
from ..ld_proofs.suites.bbs_bls_signature_2020 import BbsBlsSignature2020
from ..ld_proofs.suites.bbs_bls_signature_proof_2020 import BbsBlsSignatureProof2020
from ..ld_proofs.suites.ed25519_signature_2018 import Ed25519Signature2018
from ..ld_proofs.suites.ed25519_signature_2020 import Ed25519Signature2020
from ..ld_proofs.suites.linked_data_proof import LinkedDataProof
from ..ld_proofs.validation_result import DocumentVerificationResult
from ..vc_ld.models.presentation import VerifiablePresentation
from ..vc_ld.validation_result import PresentationVerificationResult
from .external_suite import ExternalSuiteNotFoundError, ExternalSuiteProvider
from .issue import issue as ldp_issue
from .models.credential import VerifiableCredential
from .models.linked_data_proof import LDProof
from .models.options import LDProofVCOptions
from .prove import sign_presentation
from .verify import verify_credential, verify_presentation

SignatureTypes = Union[
    Type[Ed25519Signature2018],
    Type[Ed25519Signature2020],
    Type[EcdsaSecp256r1Signature2019],
    Type[BbsBlsSignature2020],
]
ProofTypes = Union[
    Type[Ed25519Signature2018],
    Type[Ed25519Signature2020],
    Type[EcdsaSecp256r1Signature2019],
    Type[BbsBlsSignature2020],
    Type[BbsBlsSignatureProof2020],
]
SUPPORTED_ISSUANCE_PROOF_PURPOSES = {
    CredentialIssuancePurpose.term,
    AuthenticationProofPurpose.term,
}
SUPPORTED_V2_ISSUANCE_PROOF_TYPES = [
    Ed25519Signature2020.signature_type,
    BbsBlsSignature2020.signature_type,
]
SIGNATURE_SUITE_KEY_TYPE_MAPPING: Dict[SignatureTypes, KeyType] = {
    Ed25519Signature2018: ED25519,
    Ed25519Signature2020: ED25519,
    EcdsaSecp256r1Signature2019: P256,
}
PROOF_KEY_TYPE_MAPPING = cast(Dict[ProofTypes, KeyType], SIGNATURE_SUITE_KEY_TYPE_MAPPING)


# We only want to add bbs suites to supported if the module is installed
if BbsBlsSignature2020.BBS_SUPPORTED:
    SIGNATURE_SUITE_KEY_TYPE_MAPPING[BbsBlsSignature2020] = BLS12381G2
    PROOF_KEY_TYPE_MAPPING[BbsBlsSignatureProof2020] = BLS12381G2


PROOF_TYPE_SIGNATURE_SUITE_MAPPING: Dict[str, SignatureTypes] = {
    suite.signature_type: suite for suite in SIGNATURE_SUITE_KEY_TYPE_MAPPING
}


# key_type -> set of signature types mappings
KEY_TYPE_SIGNATURE_TYPE_MAPPING = {
    key_type: {
        suite.signature_type
        for suite, kt in SIGNATURE_SUITE_KEY_TYPE_MAPPING.items()
        if kt == key_type
    }
    for key_type in SIGNATURE_SUITE_KEY_TYPE_MAPPING.values()
}


class VcLdpManagerError(Exception):
    """Generic VcLdpManager Error."""


class VcLdpManager:
    """Class for managing Linked Data Proof signatures over JSON-LD formatted W3C VCs."""

    def __init__(self, profile: Profile):
        """Initialize the VC LD Proof Manager."""
        self.profile = profile

    async def _did_info_for_did(self, did: str) -> DIDInfo:
        """Get the did info for specified did.

        If the did starts with did:sov it will remove the prefix for
        backwards compatibility with not fully qualified did.

        Args:
            did (str): The did to retrieve from the wallet.

        Raises:
            WalletNotFoundError: If the did is not found in the wallet.

        Returns:
            DIDInfo: did information

        """
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)

            # If the did starts with did:sov we need to query without
            if did.startswith("did:sov:"):
                return await wallet.get_local_did(did.replace("did:sov:", ""))

            # All other methods we can just query
            return await wallet.get_local_did(did)

    async def assert_can_issue_with_id_and_proof_type(
        self, issuer_id: Optional[str], proof_type: Optional[str]
    ):
        """Assert that it is possible to issue using the specified id and proof type.

        Args:
            issuer_id (str): The issuer id
            proof_type (str): the signature suite proof type

        Raises:
            VcLdpManagerError:
                - If the proof type is not supported
                - If the issuer id is not a did
                - If the did is not found in th wallet
                - If the did does not support to create signatures for the proof type

        """
        if not issuer_id or not proof_type:
            raise VcLdpManagerError(
                "Issuer id and proof type are required to issue a credential."
            )

        try:
            # Check if it is a proof type we can issue with
            if proof_type not in PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys():
                raise VcLdpManagerError(
                    f"Unable to sign credential with unsupported proof type {proof_type}."
                    f" Supported proof types: {PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys()}"
                )

            if not issuer_id.startswith("did:"):
                raise VcLdpManagerError(
                    f"Unable to issue credential with issuer id: {issuer_id}."
                    " Only issuance with DIDs is supported"
                )

            # Retrieve did from wallet. Will throw if not found
            did = await self._did_info_for_did(issuer_id)

            # Raise error if we cannot issue a credential with this proof type
            # using this DID from
            did_proof_types = KEY_TYPE_SIGNATURE_TYPE_MAPPING[did.key_type]
            if proof_type not in did_proof_types:
                raise VcLdpManagerError(
                    f"Unable to issue credential with issuer id {issuer_id} and proof "
                    f"type {proof_type}. DID only supports proof types {did_proof_types}"
                )

        except WalletNotFoundError:
            raise VcLdpManagerError(
                f"Issuer did {issuer_id} not found."
                " Unable to issue credential with this DID."
            )

    async def _get_suite(
        self,
        *,
        proof_type: str,
        verification_method: str,
        proof: dict,
        did_info: DIDInfo,
    ):
        """Get signature suite for issuance of verification."""
        # Try to get suite from external provider first
        try:
            if (provider := self.profile.inject_or(ExternalSuiteProvider)) and (
                suite := await provider.get_suite(
                    self.profile, proof_type, proof, verification_method, did_info
                )
            ):
                return suite
        except ExternalSuiteNotFoundError as error:
            raise VcLdpManagerError(
                f"Unable to get signature suite for proof type {proof_type} "
                "using external provider."
            ) from error

        # Get signature class based on proof type
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]

        # Generically create signature class
        return SignatureClass(
            verification_method=verification_method,
            proof=proof,
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass],
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )

    def _get_proof_purpose(
        self,
        *,
        proof_purpose: Optional[str] = None,
        challenge: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> ProofPurpose:
        """Get the proof purpose for a credential.

        Args:
            proof_purpose (str): The proof purpose string value
            challenge (str, optional): Challenge
            domain (str, optional): domain

        Raises:
            VcLdpManagerError:
                - If the proof purpose is not supported.
                - [authentication] If challenge is missing.

        Returns:
            ProofPurpose: Proof purpose instance that can be used for issuance.

        """
        # Default proof purpose is assertionMethod
        proof_purpose = proof_purpose or CredentialIssuancePurpose.term

        if proof_purpose == CredentialIssuancePurpose.term:
            return CredentialIssuancePurpose()
        elif proof_purpose == AuthenticationProofPurpose.term:
            # assert challenge is present for authentication proof purpose
            if not challenge:
                raise VcLdpManagerError(
                    f"Challenge is required for '{proof_purpose}' proof purpose."
                )

            return AuthenticationProofPurpose(challenge=challenge, domain=domain)
        else:
            raise VcLdpManagerError(
                f"Unsupported proof purpose: {proof_purpose}. "
                f"Supported proof types are: {SUPPORTED_ISSUANCE_PROOF_PURPOSES}"
            )

    async def prepare_credential(
        self,
        credential: VerifiableCredential,
        options: LDProofVCOptions,
        holder_did: Optional[str] = None,
    ) -> VerifiableCredential:
        """Prepare a credential for issuance."""
        # Limit VCDM 2.0 with Ed25519Signature2020
        if (
            credential.context_urls[0] == CREDENTIALS_CONTEXT_V2_URL
            and options.proof_type not in SUPPORTED_V2_ISSUANCE_PROOF_TYPES
        ):
            raise VcLdpManagerError(
                f"Supported VC 2.0 proof types are: {SUPPORTED_V2_ISSUANCE_PROOF_TYPES}."
            )

        # Add BBS context if not present yet
        if (
            options.proof_type == BbsBlsSignature2020.signature_type
            and SECURITY_CONTEXT_BBS_URL not in credential.context_urls
        ):
            credential.add_context(SECURITY_CONTEXT_BBS_URL)
        # Add ED25519-2020 context if not present yet
        elif (
            options.proof_type == Ed25519Signature2020.signature_type
            and SECURITY_CONTEXT_ED25519_2020_URL not in credential.context_urls
        ):
            credential.add_context(SECURITY_CONTEXT_ED25519_2020_URL)

        # Permit late binding of credential subject:
        # IFF credential subject doesn't already have an id, add holder_did as
        # credentialSubject.id (if provided)
        subject = credential.credential_subject

        # TODO if credential subject is a list, we're only binding the first...
        # How should this be handled?
        if isinstance(subject, list):
            subject = subject[0]

        if (
            not credential.issuance_date
            and credential.context_urls[0] == CREDENTIALS_CONTEXT_V1_URL
        ):
            credential.issuance_date = str(
                datetime.now(timezone.utc).isoformat("T", "seconds")
            )

        if not subject:
            raise VcLdpManagerError("Credential subject is required")

        if holder_did and holder_did.startswith("did:key") and "id" not in subject:
            subject["id"] = holder_did

        return credential

    async def prepare_presentation(
        self,
        presentation: VerifiablePresentation,
        options: LDProofVCOptions,
    ) -> VerifiableCredential:
        """Prepare a presentation for issuance."""
        # Add BBS context if not present yet
        if (
            options.proof_type == BbsBlsSignature2020.signature_type
            and SECURITY_CONTEXT_BBS_URL not in presentation.context_urls
        ):
            presentation.add_context(SECURITY_CONTEXT_BBS_URL)
        # Add ED25519-2020 context if not present yet
        elif (
            options.proof_type == Ed25519Signature2020.signature_type
            and SECURITY_CONTEXT_ED25519_2020_URL not in presentation.context_urls
        ):
            presentation.add_context(SECURITY_CONTEXT_ED25519_2020_URL)

        return presentation

    async def _get_suite_for_document(
        self,
        document: Union[VerifiableCredential, VerifiablePresentation],
        options: LDProofVCOptions,
    ) -> LinkedDataProof:
        if isinstance(document, VerifiableCredential):
            issuer_id = document.issuer_id
        elif isinstance(document, VerifiablePresentation):
            issuer_id = document.holder_id

        proof_type = options.proof_type

        if not issuer_id:
            raise VcLdpManagerError("Credential issuer id is required")

        if not proof_type:
            raise VcLdpManagerError("Proof type is required")

        # Assert we can issue the credential based on issuer + proof_type
        await self.assert_can_issue_with_id_and_proof_type(issuer_id, proof_type)

        # Create base proof object with options
        proof = LDProof(
            created=options.created,
            domain=options.domain,
            challenge=options.challenge,
        )

        did_info = await self._did_info_for_did(issuer_id)
        verkey_id_strategy = self.profile.context.inject(BaseVerificationKeyStrategy)
        verification_method = (
            options.verification_method
            or await verkey_id_strategy.get_verification_method_id_for_did(
                issuer_id,
                self.profile,
                proof_type=proof_type,
                proof_purpose="assertionMethod",
            )
        )

        suite = await self._get_suite(
            proof_type=proof_type,
            verification_method=verification_method,
            proof=proof.serialize(),
            did_info=did_info,
        )

        return suite

    async def _get_all_proof_suites(self) -> List[LinkedDataProof]:
        """Get all supported suites for verifying presentation.

        Returns a list of suites instantiated with a key type, derived from
        PROOF_KEY_TYPE_MAPPING entries.
        """
        return [
            # Satisfy type checks with a cast to LinkedDataProof
            cast(
                LinkedDataProof,
                # Instantiate suite with a key type
                SuiteClass(
                    key_pair=WalletKeyPair(profile=self.profile, key_type=key_type),
                ),
            )
            # for each suite class -> key_type pair from PROOF_KEY_TYPE_MAPPING
            for SuiteClass, key_type in PROOF_KEY_TYPE_MAPPING.items()
        ]

    async def issue(
        self, credential: VerifiableCredential, options: LDProofVCOptions
    ) -> VerifiableCredential:
        """Sign a VC with a Linked Data Proof."""
        credential = await self.prepare_credential(credential, options)

        # Get signature suite, proof purpose and document loader
        suite = await self._get_suite_for_document(credential, options)
        proof_purpose = self._get_proof_purpose(
            proof_purpose=options.proof_purpose,
            challenge=options.challenge,
            domain=options.domain,
        )
        document_loader = self.profile.inject(DocumentLoader)

        vc = await ldp_issue(
            credential=credential.serialize(),
            suite=suite,
            document_loader=document_loader,
            purpose=proof_purpose,
        )
        return VerifiableCredential.deserialize(vc)

    async def store_credential(
        self,
        vc: VerifiableCredential,
        cred_id: Optional[str] = None,
    ) -> VCRecord:
        """Store a verifiable credential."""

        # Saving expanded type as a cred_tag
        document_loader = self.profile.inject(DocumentLoader)
        expanded = jsonld.expand(
            vc.serialize(), options={"documentLoader": document_loader}
        )
        types = JsonLdProcessor.get_values(
            expanded[0],
            "@type",
        )
        vc_record = VCRecord(
            contexts=vc.context_urls,
            expanded_types=types,
            issuer_id=vc.issuer_id,
            subject_ids=vc.credential_subject_ids,
            schema_ids=[],  # Schemas not supported yet
            proof_types=[vc.proof.type],
            cred_value=vc.serialize(),
            given_id=vc.id,
            record_id=cred_id,
            cred_tags=None,  # Tags should be derived from credential values
        )

        async with self.profile.session() as session:
            vc_holder = session.inject(VCHolder)

            await vc_holder.store_credential(vc_record)

        return vc_record

    async def verify_credential(
        self, vc: VerifiableCredential
    ) -> DocumentVerificationResult:
        """Verify a VC with a Linked Data Proof."""
        return await verify_credential(
            credential=vc.serialize(),
            suites=await self._get_all_proof_suites(),
            document_loader=self.profile.inject(DocumentLoader),
        )

    async def prove(
        self, presentation: VerifiablePresentation, options: LDProofVCOptions
    ) -> VerifiablePresentation:
        """Sign a VP with a Linked Data Proof."""
        presentation = await self.prepare_presentation(presentation, options)

        # Get signature suite, proof purpose and document loader
        suite = await self._get_suite_for_document(presentation, options)
        proof_purpose = self._get_proof_purpose(
            proof_purpose=options.proof_purpose,
            challenge=options.challenge,
            domain=options.domain,
        )
        document_loader = self.profile.inject(DocumentLoader)

        vp = await sign_presentation(
            presentation=presentation.serialize(),
            suite=suite,
            document_loader=document_loader,
            purpose=proof_purpose,
        )
        return VerifiablePresentation.deserialize(vp)

    async def verify_presentation(
        self, vp: VerifiablePresentation, options: LDProofVCOptions
    ) -> PresentationVerificationResult:
        """Verify a VP with a Linked Data Proof."""

        if not options.challenge:
            raise VcLdpManagerError("Challenge is required for verifying a VP")

        return await verify_presentation(
            presentation=vp.serialize(),
            suites=await self._get_all_proof_suites(),
            document_loader=self.profile.inject(DocumentLoader),
            challenge=options.challenge,
        )
