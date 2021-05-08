"""Indy DID Resolver.

Resolution is performed using the IndyLedger class.
"""

from typing import Sequence

from pydid import DID, DIDDocumentBuilder, VerificationSuite

from ...config.injection_context import InjectionContext
from ...core.profile import Profile
from ...ledger.indy import IndySdkLedger, EndpointType
from ...ledger.base import BaseLedger
from ...ledger.error import LedgerError
from ..base import BaseDIDResolver, DIDNotFound, ResolverError, ResolverType


class NoIndyLedger(ResolverError):
    """Raised when there is no indy ledger instance configured."""


class IndyDIDResolver(BaseDIDResolver):
    """Indy DID Resolver."""

    VERIFICATION_METHOD_TYPE = "Ed25519VerificationKey2018"
    AGENT_SERVICE_TYPE = "did-communication"
    SUITE = VerificationSuite(VERIFICATION_METHOD_TYPE, "publicKeyBase58")

    def __init__(self):
        """Initialize Indy Resolver."""
        super().__init__(ResolverType.NATIVE)

    async def setup(self, context: InjectionContext):
        """Perform required setup for Indy DID resolution."""

    @property
    def supported_methods(self) -> Sequence[str]:
        """Return supported methods of Indy DID Resolver."""
        return ["sov"]

    async def _resolve(self, profile: Profile, did: str) -> dict:
        """Resolve an indy DID."""
        ledger = profile.inject(BaseLedger, required=False)
        if not ledger or not isinstance(ledger, IndySdkLedger):
            raise NoIndyLedger("No Indy ledger instance is configured.")

        try:
            async with ledger:
                recipient_key = await ledger.get_key_for_did(did)
                endpoints = await ledger.get_all_endpoints_for_did(did)
        except LedgerError as err:
            raise DIDNotFound(f"DID {did} could not be resolved") from err

        builder = DIDDocumentBuilder(DID(did))

        vmethod = builder.verification_methods.add(
            ident="key-1", suite=self.SUITE, material=recipient_key
        )
        builder.authentication.reference(vmethod.id)
        builder.assertion_method.reference(vmethod.id)
        if endpoints:
            for type_, endpoint in endpoints.items():
                if type_ == EndpointType.ENDPOINT.indy:
                    # TODO add priority
                    builder.services.add_didcomm(
                        ident=self.AGENT_SERVICE_TYPE,
                        type_=self.AGENT_SERVICE_TYPE,
                        endpoint=endpoint,
                        priority=1,
                        recipient_keys=[vmethod],
                        routing_keys=[],
                    )
                else:
                    # Accept all service types for now
                    builder.services.add(
                        ident=type_,
                        type_=type_,
                        endpoint=endpoint,
                    )

        result = builder.build()
        return result.serialize()
