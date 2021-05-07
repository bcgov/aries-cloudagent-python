import logging

from pydid import DID, DIDDocument, DIDDocumentBuilder, VerificationSuite

from ..wallet.base import BaseWallet
from ..core.profile import ProfileSession
from .util import retrieve_did_document, save_did_document, VerificationMethod

LOGGER = logging.getLogger(__name__)


AGENT_SERVICE_TYPE = "did-communication"


class DIDWeb():
    """Class for managing a did:web DID document."""

    def __init__(self, session: ProfileSession):
        """
        Initialize DIDWeb.

        Args:
            session: The current profile session
        """
        self._session = session

    @property
    def session(self) -> ProfileSession:
        """
        Accessor for the current profile session.

        Returns:
            The current profile session

        """
        return self._session

    async def create_from_wallet(
        self, did: DID, extras=None
    ) -> str:
        """Add content from wallet to DID document."""
        wallet = self.session.inject(BaseWallet, required=False)
        public_did_obj = await wallet.get_public_did()
        recipient_key = public_did_obj.verkey
        endpoint = public_did_obj.metadata["endpoint"]
        did_document = DIDDocument
        builder = DIDDocumentBuilder(did)
        suite = VerificationSuite(VerificationMethod.ED25519.value, "publicKeyBase58")
        vmethod = builder.verification_methods.add(
            ident="key-1", suite=suite, material=recipient_key
        )
        builder.authentication.reference(vmethod.id)
        builder.assertion_method.reference(vmethod.id)
        if endpoint:
            builder.services.add_didcomm(
                ident=AGENT_SERVICE_TYPE,
                type_=AGENT_SERVICE_TYPE,
                endpoint=endpoint,
                recipient_keys=[vmethod],
                routing_keys=[],
            )

        if extras is not None:
            if "verification_methods" in extras:
                verification_methods = extras["verification_methods"]
                for idx, verification_method in enumerate(verification_methods):
                    did = verification_method["did"]
                    did_info = await wallet.get_local_did(did)
                    key_type = did_info.key_type
                    suite = VerificationSuite(
                        VerificationMethod[key_type.name].value,
                        "publicKeyBase58"
                    )
                    vmethod = builder.verification_methods.add(
                        # +2 since there's already the key related to the public DID
                        ident=f"key-{idx+2}", suite=suite, material=did_info.verkey
                    )
                    if "verification_relationships" in verification_method:
                        vrelations = verification_method["verification_relationships"]
                        for vrelation in vrelations:
                            getattr(builder, vrelation).reference(vmethod.id)

            if "services" in extras:
                # TODO: Implement adding custom services
                None

        did_document = builder.build()

        await save_did_document(did_document, self._session)
        self._did_document = did_document
        return did_document.serialize()

    async def create(self, did_document) -> str:
        await save_did_document(None, self._session)
        self._did_document = did_document
        return did_document

    async def delete(self):
        await save_did_document(None, self._session)
        return None

    async def retrieve(self) -> str:
        did_document = await retrieve_did_document(self._session)
        if did_document:
            return did_document.serialize()
        else:
            return None
