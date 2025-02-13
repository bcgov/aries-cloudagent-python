"""DID manager for Indy."""

from aries_askar import AskarError, Key

from ...core.profile import Profile
from ...utils.general import strip_did_prefix
from ...wallet.askar import CATEGORY_DID
from ...wallet.crypto import validate_seed
from ...wallet.did_method import INDY, DIDMethods
from ...wallet.did_parameters_validation import DIDParametersValidation
from ...wallet.error import WalletError
from ...wallet.key_type import ED25519, KeyType, KeyTypes
from ...wallet.util import bytes_to_b58


class DidIndyManager:
    """DID manager for Indy."""

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID  manager."""
        self.profile = profile

    async def _get_holder_defined_did(self, options: dict) -> str | None:
        async with self.profile.session() as session:
            did_methods = session.inject(DIDMethods)
            indy_method = did_methods.from_method(INDY.method_name)

            if indy_method.holder_defined_did() and options.get("did"):
                return strip_did_prefix(options.get("did"))

        return None

    async def _get_key_type(self, key_type: str) -> KeyType:
        async with self.profile.session() as session:
            key_types = session.inject(KeyTypes)
            return key_types.from_key_type(key_type) or ED25519

    def _create_key_pair(self, options: dict, key_type: KeyType) -> Key:
        seed = options.get("seed")
        if seed:
            seed = validate_seed(seed)
            return Key.from_secret_bytes(key_type, seed)
        return Key.generate(key_type)

    async def register(self, options: dict) -> dict:
        """Register a DID Indy."""
        options = options or {}

        key_type = await self._get_key_type(options.get("key_type") or ED25519)
        did_validation = DIDParametersValidation(self.profile.inject(DIDMethods))
        did_validation.validate_key_type(INDY, key_type)

        key_pair = self._create_key_pair(options, key_type.key_type)
        verkey_bytes = key_pair.get_public_bytes()
        verkey = bytes_to_b58(verkey_bytes)

        nym = did_validation.validate_or_derive_did(
            INDY, ED25519, verkey_bytes, (await self._get_holder_defined_did(options))
        )
        did = f"did:indy:{nym}"

        async with self.profile.session() as session:
            try:
                await session.handle.insert_key(verkey, key_pair)
                await session.handle.insert(
                    CATEGORY_DID,
                    did,
                    value_json={
                        "did": did,
                        "method": INDY.method_name,
                        "verkey": verkey,
                        "verkey_type": ED25519.key_type,
                        "metadata": {},
                    },
                    tags={
                        "method": INDY.method_name,
                        "verkey": verkey,
                        "verkey_type": ED25519.key_type,
                    },
                )
            except AskarError as err:
                raise WalletError(f"Error registering DID: {err}") from err

        return {
            "did": did,
            "verkey": verkey,
        }
