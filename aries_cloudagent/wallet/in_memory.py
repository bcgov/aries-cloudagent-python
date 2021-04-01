"""In-memory implementation of BaseWallet interface."""

import asyncio
from typing import Sequence, Tuple

from ..core.in_memory import InMemoryProfile

from .base import BaseWallet, KeyInfo, DIDInfo
from .crypto import (
    create_keypair,
    random_seed,
    validate_seed,
    sign_message,
    verify_signed_message,
    encode_pack_message,
    decode_pack_message,
)
from .error import WalletError, WalletDuplicateError, WalletNotFoundError
from .util import b58_to_bytes, bytes_to_b58


class InMemoryWallet(BaseWallet):
    """In-memory wallet implementation."""

    def __init__(self, profile: InMemoryProfile):
        """
        Initialize an `InMemoryWallet` instance.

        Args:
            profile: The in-memory profile used to store state

        """
        self.profile = profile

    async def create_signing_key(
        self, seed: str = None, metadata: dict = None
    ) -> KeyInfo:
        """
        Create a new public/private signing keypair.

        Args:
            seed: Seed to use for signing key
            metadata: Optional metadata to store with the keypair

        Returns:
            A `KeyInfo` representing the new record

        Raises:
            WalletDuplicateError: If the resulting verkey already exists in the wallet

        """
        seed = validate_seed(seed) or random_seed()
        verkey, secret = create_keypair(seed)
        verkey_enc = bytes_to_b58(verkey)
        if verkey_enc in self.profile.keys:
            raise WalletDuplicateError("Verification key already present in wallet")
        self.profile.keys[verkey_enc] = {
            "seed": seed,
            "secret": secret,
            "verkey": verkey_enc,
            "metadata": metadata.copy() if metadata else {},
        }
        return KeyInfo(verkey_enc, self.profile.keys[verkey_enc]["metadata"].copy())

    async def get_signing_key(self, verkey: str) -> KeyInfo:
        """
        Fetch info for a signing keypair.

        Args:
            verkey: The verification key of the keypair

        Returns:
            A `KeyInfo` representing the keypair

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """
        if verkey not in self.profile.keys:
            raise WalletNotFoundError("Key not found: {}".format(verkey))
        key = self.profile.keys[verkey]
        return KeyInfo(key["verkey"], key["metadata"].copy())

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """
        Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """
        if verkey not in self.profile.keys:
            raise WalletNotFoundError("Key not found: {}".format(verkey))
        self.profile.keys[verkey]["metadata"] = metadata.copy() if metadata else {}

    async def rotate_did_keypair_start(self, did: str, next_seed: str = None) -> str:
        """
        Begin key rotation for DID that wallet owns: generate new keypair.

        Args:
            did: signing DID
            next_seed: incoming replacement seed (default random)

        Returns:
            The new verification key

        Raises:
            WalletNotFoundError: if wallet does not own DID

        """
        if did not in self.profile.local_dids:
            raise WalletNotFoundError("Wallet owns no such DID: {}".format(did))

        key_info = await self.create_signing_key(next_seed, {"did": did})
        return key_info.verkey

    async def rotate_did_keypair_apply(self, did: str) -> None:
        """
        Apply temporary keypair as main for DID that wallet owns.

        Args:
            did: signing DID

        Raises:
            WalletNotFoundError: if wallet does not own DID
            WalletError: if wallet has not started key rotation

        """
        if did not in self.profile.local_dids:
            raise WalletNotFoundError("Wallet owns no such DID: {}".format(did))
        temp_keys = [
            k
            for k in self.profile.keys
            if self.profile.keys[k]["metadata"].get("did") == did
        ]
        if not temp_keys:
            raise WalletError("Key rotation not in progress for DID: {}".format(did))
        verkey_enc = temp_keys[0]

        self.profile.local_dids[did].update(
            {
                "seed": self.profile.keys[verkey_enc]["seed"],
                "secret": self.profile.keys[verkey_enc]["secret"],
                "verkey": verkey_enc,
            }
        )
        self.profile.keys.pop(verkey_enc)
        return DIDInfo(did, verkey_enc, self.profile.local_dids[did]["metadata"].copy())

    async def create_local_did(
        self,
        seed: str = None,
        did: str = None,
        method_name: str = None,
        metadata: dict = None,
    ) -> DIDInfo:
        """
        Create and store a new local DID.

        Args:
            seed: Optional seed to use for DID
            did: The DID to use
            method_name: The DID method to use
            metadata: Metadata to store with DID

        Returns:
            A `DIDInfo` instance representing the created DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet

        """
        seed = validate_seed(seed) or random_seed()
        verkey, secret = create_keypair(seed)
        verkey_enc = bytes_to_b58(verkey)
        if not did:
            did = bytes_to_b58(verkey[:16])
        if method_name:
            did = f"did:{method_name}{did}"
        if (
            did in self.profile.local_dids
            and self.profile.local_dids[did]["verkey"] != verkey_enc
        ):
            raise WalletDuplicateError("DID already exists in wallet")
        self.profile.local_dids[did] = {
            "seed": seed,
            "secret": secret,
            "verkey": verkey_enc,
            "metadata": metadata.copy() if metadata else {},
        }
        return DIDInfo(did, verkey_enc, self.profile.local_dids[did]["metadata"].copy())

    def _get_did_info(self, did: str) -> DIDInfo:
        """
        Convert internal DID record to DIDInfo.

        Args:
            did: The DID to get info for

        Returns:
            A `DIDInfo` instance for the DID

        """
        info = self.profile.local_dids[did]
        return DIDInfo(did=did, verkey=info["verkey"], metadata=info["metadata"].copy())

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """
        Get list of defined local DIDs.

        Returns:
            A list of locally stored DIDs as `DIDInfo` instances

        """
        ret = [self._get_did_info(did) for did in self.profile.local_dids]
        return ret

    async def get_local_did(self, did: str) -> DIDInfo:
        """
        Find info for a local DID.

        Args:
            did: The DID for which to get info

        Returns:
            A `DIDInfo` instance representing the found DID

        Raises:
            WalletNotFoundError: If the DID is not found

        """
        if did not in self.profile.local_dids:
            raise WalletNotFoundError("DID not found: {}".format(did))
        return self._get_did_info(did)

    async def get_local_did_for_verkey(self, verkey: str) -> DIDInfo:
        """
        Resolve a local DID from a verkey.

        Args:
            verkey: The verkey for which to get the local DID

        Returns:
            A `DIDInfo` instance representing the found DID

        Raises:
            WalletNotFoundError: If the verkey is not found

        """
        for did, info in self.profile.local_dids.items():
            if info["verkey"] == verkey:
                return self._get_did_info(did)
        raise WalletNotFoundError("Verkey not found: {}".format(verkey))

    async def replace_local_did_metadata(self, did: str, metadata: dict):
        """
        Replace metadata for a local DID.

        Args:
            did: The DID for which to replace metadata
            metadata: The new metadata

        Raises:
            WalletNotFoundError: If the DID doesn't exist

        """
        if did not in self.profile.local_dids:
            raise WalletNotFoundError("Unknown DID: {}".format(did))
        self.profile.local_dids[did]["metadata"] = metadata.copy() if metadata else {}

    def _get_private_key(self, verkey: str) -> bytes:
        """
        Resolve private key for a wallet DID.

        Args:
            verkey: The verkey to lookup

        Returns:
            The private key

        Raises:
            WalletError: If the private key is not found

        """

        keys_and_dids = list(self.profile.local_dids.values()) + list(
            self.profile.keys.values()
        )
        for info in keys_and_dids:
            if info["verkey"] == verkey:
                return info["secret"]

        raise WalletError("Private key not found for verkey: {}".format(verkey))

    async def sign_message(self, message: bytes, from_verkey: str) -> bytes:
        """
        Sign a message using the private key associated with a given verkey.

        Args:
            message: Message bytes to sign
            from_verkey: The verkey to use to sign

        Returns:
            A signature

        Raises:
            WalletError: If the message is not provided
            WalletError: If the verkey is not provided

        """
        if not message:
            raise WalletError("Message not provided")
        if not from_verkey:
            raise WalletError("Verkey not provided")
        secret = self._get_private_key(from_verkey)
        signature = sign_message(message, secret)
        return signature

    async def verify_message(
        self, message: bytes, signature: bytes, from_verkey: str
    ) -> bool:
        """
        Verify a signature against the public key of the signer.

        Args:
            message: Message to verify
            signature: Signature to verify
            from_verkey: Verkey to use in verification

        Returns:
            True if verified, else False

        Raises:
            WalletError: If the verkey is not provided
            WalletError: If the signature is not provided
            WalletError: If the message is not provided

        """
        if not from_verkey:
            raise WalletError("Verkey not provided")
        if not signature:
            raise WalletError("Signature not provided")
        if not message:
            raise WalletError("Message not provided")
        verkey_bytes = b58_to_bytes(from_verkey)
        verified = verify_signed_message(signature + message, verkey_bytes)
        return verified

    async def pack_message(
        self, message: str, to_verkeys: Sequence[str], from_verkey: str = None
    ) -> bytes:
        """
        Pack a message for one or more recipients.

        Args:
            message: The message to pack
            to_verkeys: List of verkeys for which to pack
            from_verkey: Sender verkey from which to pack

        Returns:
            The resulting packed message bytes

        Raises:
            WalletError: If the message is not provided

        """
        if message is None:
            raise WalletError("Message not provided")

        keys_bin = [b58_to_bytes(key) for key in to_verkeys]
        secret = self._get_private_key(from_verkey) if from_verkey else None
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: encode_pack_message(message, keys_bin, secret)
        )
        return result

    async def unpack_message(self, enc_message: bytes) -> Tuple[str, str, str]:
        """
        Unpack a message.

        Args:
            enc_message: The packed message bytes

        Returns:
            A tuple: (message, from_verkey, to_verkey)

        Raises:
            WalletError: If the message is not provided
            WalletError: If there is a problem unpacking the message

        """
        if not enc_message:
            raise WalletError("Message not provided")
        try:
            (
                message,
                from_verkey,
                to_verkey,
            ) = await asyncio.get_event_loop().run_in_executor(
                None, lambda: decode_pack_message(enc_message, self._get_private_key)
            )
        except ValueError as e:
            raise WalletError("Message could not be unpacked: {}".format(str(e)))
        return message, from_verkey, to_verkey
