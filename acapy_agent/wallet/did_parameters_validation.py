"""Tooling to validate DID creation parameters."""

import hashlib
from typing import Optional

from acapy_agent.did.did_key import DIDKey
from acapy_agent.wallet.did_method import (
    INDY,
    KEY,
    SOV,
    DIDMethod,
    DIDMethods,
    HolderDefinedDid,
)
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import KeyType
from acapy_agent.wallet.util import bytes_to_b58


class DIDParametersValidation:
    """A utility class to check compatibility of provided DID creation parameters."""

    def __init__(self, did_methods: DIDMethods):
        """:param did_methods: DID method registry relevant for the validation."""
        self.did_methods = did_methods

    @staticmethod
    def validate_key_type(method: DIDMethod, key_type: KeyType):
        """Validate compatibility of the DID method with the desired key type."""
        # validate key_type
        if not method.supports_key_type(key_type):
            raise WalletError(
                f"Invalid key type {key_type.key_type}"
                f" for DID method {method.method_name}"
            )

    def validate_or_derive_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        verkey: bytes,
        did: Optional[str],
    ) -> str:
        """Validate compatibility of the provided did (if any) with the given DID method.

        If no DID was provided, automatically derive one for methods that support it.
        """
        if method.holder_defined_did() == HolderDefinedDid.NO and did:
            raise WalletError(
                f"Not allowed to set DID for DID method '{method.method_name}'"
            )
        elif method.holder_defined_did() == HolderDefinedDid.REQUIRED and not did:
            raise WalletError(f"Providing a DID is required {method.method_name}")
        elif not self.did_methods.registered(method.method_name):
            raise WalletError(
                f"Unsupported DID method for current storage: {method.method_name}"
            )

        # We need some did method specific handling. If more did methods
        # are added it is probably better create a did method specific handler
        elif method == KEY:
            return DIDKey.from_public_key(verkey, key_type).did
        elif method == SOV:
            return bytes_to_b58(verkey[:16]) if not did else did
        elif method == INDY:
            return bytes_to_b58(hashlib.sha256(verkey).digest()[:16]) if not did else did

        return did
