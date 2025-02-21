"""Multikey class."""

from ...core.profile import ProfileSession
from ..base import BaseWallet
from ..key_type import ED25519, P256, BLS12381G1G2, KeyType
from ..util import b58_to_bytes, bytes_to_b58
from ...utils.multiformats import multibase
from ...wallet.error import WalletNotFoundError
from ...resolver.did_resolver import DIDResolver

DEFAULT_ALG = "ed25519"
ALG_MAPPINGS = {
    "ed25519": {
        "key_type": ED25519,
        "multikey_prefix": "z6Mk",
        "prefix_hex": "ed01",
        "prefix_length": 2,
    },
    "p256": {
        "key_type": P256,
        "multikey_prefix": "zDn",
        "prefix_hex": "8024",
        "prefix_length": 2,
    },
    "bls12381g2": {
        "key_type": BLS12381G1G2,
        "multikey_prefix": "zUC7",
        "prefix_hex": "eb01",
        "prefix_length": 2,
    },
}


def multikey_to_verkey(multikey: str):
    """Transform multikey to verkey."""

    alg = key_type_from_multikey(multikey).key_type
    prefix_length = ALG_MAPPINGS[alg]["prefix_length"]
    public_bytes = bytes(bytearray(multibase.decode(multikey))[prefix_length:])

    return bytes_to_b58(public_bytes)


def verkey_to_multikey(verkey: str, alg: str):
    """Transform verkey to multikey."""

    prefix_hex = ALG_MAPPINGS[alg]["prefix_hex"]
    prefixed_key_hex = f"{prefix_hex}{b58_to_bytes(verkey).hex()}"

    return multibase.encode(bytes.fromhex(prefixed_key_hex), "base58btc")


def key_type_from_multikey(multikey: str) -> KeyType:
    """Derive key_type class from multikey prefix."""
    for mapping in ALG_MAPPINGS:
        if multikey.startswith(ALG_MAPPINGS[mapping]["multikey_prefix"]):
            return ALG_MAPPINGS[mapping]["key_type"]

    raise MultikeyManagerError(f"Unsupported key algorithm for multikey {multikey}.")


class MultikeyManagerError(Exception):
    """Generic MultikeyManager Error."""


class MultikeyManager:
    """Class for managing wallet keys."""

    def __init__(self, session: ProfileSession):
        """Initialize the MultikeyManager."""

        self.session: ProfileSession = session
        self.wallet: BaseWallet = session.inject(BaseWallet)

    async def resolve_multikey_from_verification_method(self, kid: str):
        """Derive a multikey from the verification method."""
        resolver = self.session.inject(DIDResolver)
        verification_method = await resolver.dereference(
            profile=self.session.profile, did_url=kid
        )

        if verification_method.type == "Multikey":
            multikey = verification_method.public_key_multibase

        elif verification_method.type == "Ed25519VerificationKey2018":
            multikey = verkey_to_multikey(
                verification_method.public_key_base58, alg="ed25519"
            )

        elif verification_method.type == "Ed25519VerificationKey2020":
            multikey = verification_method.public_key_multibase

        else:
            raise MultikeyManagerError("Unknown verification method type.")

        return multikey

    def key_type_from_multikey(self, multikey: str):
        """Derive key_type class from multikey prefix."""
        for mapping in ALG_MAPPINGS:
            if multikey.startswith(ALG_MAPPINGS[mapping]["multikey_prefix"]):
                return ALG_MAPPINGS[mapping]["key_type"]

        raise MultikeyManagerError(f"Unsupported key algorithm for multikey {multikey}.")

    async def kid_exists(self, kid: str):
        """Check if kid exists."""

        try:
            key = await self.wallet.get_key_by_kid(kid=kid)

            if key:
                return True

        except (WalletNotFoundError, AttributeError):
            return False

    async def from_kid(self, kid: str):
        """Fetch a single key."""

        key_info = await self.wallet.get_key_by_kid(kid=kid)

        return {
            "kid": key_info.kid,
            "multikey": verkey_to_multikey(
                key_info.verkey, alg=key_info.key_type.key_type
            ),
        }

    async def from_multikey(self, multikey: str):
        """Fetch a single key."""

        key_info = await self.wallet.get_signing_key(verkey=multikey_to_verkey(multikey))

        return {
            "kid": key_info.kid,
            "multikey": verkey_to_multikey(
                key_info.verkey, alg=key_info.key_type.key_type
            ),
        }

    async def create(self, seed: str = None, kid: str = None, alg: str = DEFAULT_ALG):
        """Create a new key pair."""

        if alg not in ALG_MAPPINGS:
            raise MultikeyManagerError(
                f"Unknown key algorithm, use one of {list(ALG_MAPPINGS.keys())}."
            )

        if kid and await self.kid_exists(kid=kid):
            raise MultikeyManagerError(f"kid '{kid}' already exists in wallet.")

        key_type = ALG_MAPPINGS[alg]["key_type"]
        key_info = await self.wallet.create_key(key_type=key_type, seed=seed, kid=kid)

        return {
            "kid": key_info.kid,
            "multikey": verkey_to_multikey(key_info.verkey, alg=alg),
        }

    async def update(self, multikey: str, kid: str):
        """Assign a new kid to a key pair."""

        if kid and await self.kid_exists(kid=kid):
            raise MultikeyManagerError(f"kid '{kid}' already exists in wallet.")

        key_info = await self.wallet.assign_kid_to_key(
            verkey=multikey_to_verkey(multikey), kid=kid
        )

        return {
            "kid": key_info.kid,
            "multikey": verkey_to_multikey(
                key_info.verkey, alg=key_info.key_type.key_type
            ),
        }
