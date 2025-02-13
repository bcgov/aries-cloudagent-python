"""did method.py contains registry for did methods."""

from enum import Enum
from typing import Dict, List, Mapping, Optional

from .error import BaseError
from .key_type import BLS12381G2, ED25519, P256, X25519, KeyType


class HolderDefinedDid(Enum):
    """Define if a holder can specify its own did for a given method."""

    NO = "no"  # holder CANNOT provide a DID
    ALLOWED = "allowed"  # holder CAN provide a DID
    REQUIRED = "required"  # holder MUST provide a DID


class DIDMethod:
    """Class to represent a did method."""

    def __init__(
        self,
        name: str,
        key_types: List[KeyType],
        rotation: bool = False,
        holder_defined_did: HolderDefinedDid = HolderDefinedDid.NO,
    ):
        """Construct did method class."""
        self._method_name: str = name
        self._supported_key_types: List[KeyType] = key_types
        self._supports_rotation: bool = rotation
        self._holder_defined_did: HolderDefinedDid = holder_defined_did

    @property
    def method_name(self):
        """Get method name."""
        return self._method_name

    @property
    def supports_rotation(self):
        """Check rotation support."""
        return self._supports_rotation

    @property
    def supported_key_types(self):
        """Get supported key types."""
        return self._supported_key_types

    def supports_key_type(self, key_type: KeyType) -> bool:
        """Check whether the current method supports the key type."""
        return key_type in self.supported_key_types

    def holder_defined_did(self) -> HolderDefinedDid:
        """Return the did derivation policy.

        eg: did:key DIDs are derived from the verkey -> HolderDefinedDid.NO
        eg: did:web DIDs cannot be derived from key material -> HolderDefinedDid.REQUIRED
        """
        return self._holder_defined_did


SOV = DIDMethod(
    name="sov",
    key_types=[ED25519],
    rotation=True,
    holder_defined_did=HolderDefinedDid.ALLOWED,
)
INDY = DIDMethod(
    name="indy",
    key_types=[ED25519],
    rotation=True,
    holder_defined_did=HolderDefinedDid.ALLOWED,
)
KEY = DIDMethod(
    name="key",
    key_types=[ED25519, P256, BLS12381G2],
    rotation=False,
)
WEB = DIDMethod(
    name="web",
    key_types=[ED25519, BLS12381G2],
    rotation=True,
    holder_defined_did=HolderDefinedDid.REQUIRED,
)
PEER2 = DIDMethod(
    name="did:peer:2",
    key_types=[ED25519, X25519],
    rotation=False,
    holder_defined_did=HolderDefinedDid.NO,
)

PEER4 = DIDMethod(
    name="did:peer:4",
    key_types=[ED25519, X25519],
    rotation=False,
    holder_defined_did=HolderDefinedDid.NO,
)

WEBVH = DIDMethod(
    name="webvh",
    key_types=[ED25519, X25519],
    rotation=False,
    holder_defined_did=HolderDefinedDid.NO,
)


class DIDMethods:
    """DID Method class specifying DID methods with supported key types."""

    def __init__(self) -> None:
        """Construct did method registry."""
        self._registry: Dict[str, DIDMethod] = {
            SOV.method_name: SOV,
            INDY.method_name: INDY,
            KEY.method_name: KEY,
            WEB.method_name: WEB,
            PEER2.method_name: PEER2,
            PEER4.method_name: PEER4,
            WEBVH.method_name: WEBVH,
        }

    def registered(self, method: str) -> bool:
        """Check for a supported method."""
        return method in self._registry.keys()

    def register(self, method: DIDMethod):
        """Register a new did method."""
        self._registry[method.method_name] = method

    def from_method(self, method_name: str) -> Optional[DIDMethod]:
        """Retrieve a did method from method name."""
        return self._registry.get(method_name)

    def from_metadata(self, metadata: Mapping) -> Optional[DIDMethod]:
        """Get DID method instance from metadata object.

        Returns SOV if no metadata was found for backwards compatibility.
        """
        method_name: str = metadata.get("method", "sov")
        return self.from_method(method_name)

    def from_did(self, did: str) -> DIDMethod:
        """Get DID method instance from the did url."""
        method_name = did.split(":")[1] if did.startswith("did:") else SOV.method_name
        method: DIDMethod | None = self.from_method(method_name)
        if not method:
            raise BaseError(f"Unsupported did method: {method_name}")
        return method
