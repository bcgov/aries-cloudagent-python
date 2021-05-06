"""Aries-Askar implementation of BaseWallet interface."""

import asyncio
from collections import OrderedDict
import json
import logging

from typing import Optional, List, Sequence, Tuple, Union

from aries_askar import (
    crypto_box,
    crypto_box_open,
    crypto_box_random_nonce,
    crypto_box_seal,
    crypto_box_seal_open,
    AskarError,
    AskarErrorCode,
    Key,
    KeyAlg,
    Session,
)
from aries_askar.bindings import key_get_secret_bytes
from aries_askar.store import Entry
from marshmallow import ValidationError

from ..askar.profile import AskarProfileSession
from ..did.did_key import DIDKey
from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from ..ledger.error import LedgerConfigError
from ..utils.jwe import b64url, JweEnvelope, JweRecipient

from .base import BaseWallet, KeyInfo, DIDInfo
from .crypto import (
    extract_pack_recipients,
    sign_message,
    validate_seed,
    verify_signed_message,
)
from .did_method import DIDMethod
from .error import WalletError, WalletDuplicateError, WalletNotFoundError
from .key_type import KeyType
from .util import b58_to_bytes, bytes_to_b58

CATEGORY_DID = "did"

LOGGER = logging.getLogger(__name__)


def create_keypair(key_type: KeyType, seed: Union[str, bytes] = None) -> Key:
    if key_type == KeyType.ED25519:
        alg = KeyAlg.ED25519
    # elif key_type == KeyType.BLS12381G1:
    #     alg = KeyAlg.BLS12_381_G1
    elif key_type == KeyType.BLS12381G2:
        alg = KeyAlg.BLS12_381_G2
    # elif key_type == KeyType.BLS12381G1G2:
    #     alg = KeyAlg.BLS12_381_G1G2
    else:
        raise WalletError(f"Unsupported key algorithm: {key_type}")
    if seed:
        try:
            if key_type == KeyType.ED25519:
                # not a seed - it is the secret key
                seed = validate_seed(seed)
                return Key.from_secret_bytes(alg, seed)
            else:
                return Key.from_seed(alg, seed)
        except AskarError as err:
            if err.code == AskarErrorCode.INPUT:
                raise WalletError("Invalid seed for key generation") from None
    else:
        return Key.generate(alg)


def _load_did_entry(entry: Entry) -> DIDInfo:
    did_info = entry.value_json
    return DIDInfo(
        did=did_info["did"],
        verkey=did_info["verkey"],
        metadata=did_info.get("metadata"),
        method=DIDMethod.from_method(did_info.get("method", "sov")),
        key_type=KeyType.from_key_type(did_info.get("verkey_type", "ed25519")),
    )


class AskarWallet(BaseWallet):
    """Aries-Askar wallet implementation."""

    def __init__(self, session: AskarProfileSession):
        """
        Initialize a new `AskarWallet` instance.

        Args:
            session: The Askar profile session instance to use
        """
        self._session = session

    @property
    def session(self) -> Session:
        """Accessor for Askar profile session instance."""
        return self._session

    async def create_signing_key(
        self, key_type: KeyType, seed: str = None, metadata: dict = None
    ) -> KeyInfo:
        """Create a new public/private signing keypair.

        Args:
            key_type: Key type to create
            seed: Seed for key
            metadata: Optional metadata to store with the keypair

        Returns:
            A `KeyInfo` representing the new record

        Raises:
            WalletDuplicateError: If the resulting verkey already exists in the wallet
            WalletError: If there is an aries_askar error

        """

        if metadata is None:
            metadata = {}
        try:
            keypair = create_keypair(key_type, seed)
            verkey = bytes_to_b58(keypair.get_public_bytes())
            await self._session.handle.insert_key(
                verkey, keypair, metadata=json.dumps(metadata)
            )
        except AskarError as err:
            if err.code == AskarErrorCode.DUPLICATE:
                raise WalletDuplicateError(
                    "Verification key already present in wallet"
                ) from None
            raise WalletError("Error creating signing key") from err

        return KeyInfo(verkey=verkey, metadata=metadata, key_type=key_type)

    async def get_signing_key(self, verkey: str) -> KeyInfo:
        """
        Fetch info for a signing keypair.

        Args:
            verkey: The verification key of the keypair

        Returns:
            A `KeyInfo` representing the keypair

        Raises:
            WalletNotFoundError: If no keypair is associated with the verification key
            WalletError: If there is a aries_askar error

        """

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")
        key = await self._session.handle.fetch_key(verkey)
        if not key:
            raise WalletNotFoundError("Unknown key: {}".format(verkey))
        metadata = json.loads(key.metadata or "{}")
        # FIXME implement key types
        return KeyInfo(verkey=verkey, metadata=metadata, key_type=KeyType.ED25519)

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """
        Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """

        # FIXME caller should always create a transaction first

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")

        key = await self._session.handle.fetch_key(verkey, for_update=True)
        if not key:
            raise WalletNotFoundError("Keypair not found")
        await self._session.handle.update_key(
            verkey, metadata=json.dumps(metadata or {}), tags=key.tags
        )

    async def create_local_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        seed: str = None,
        did: str = None,
        metadata: dict = None,
    ) -> DIDInfo:
        """
        Create and store a new local DID.

        Args:
            method: The method to use for the DID
            key_type: The key type to use for the DID
            seed: Optional seed to use for DID
            did: The DID to use
            metadata: Metadata to store with DID

        Returns:
            A `DIDInfo` instance representing the created DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet
            WalletError: If there is a aries_askar error

        """

        # validate key_type
        if not method.supports_key_type(key_type):
            raise WalletError(
                f"Invalid key type {key_type.key_type}"
                f" for DID method {method.method_name}"
            )

        if method == DIDMethod.KEY and did:
            raise WalletError("Not allowed to set DID for DID method 'key'")

        if not metadata:
            metadata = {}
        if method not in [DIDMethod.SOV, DIDMethod.KEY]:
            raise WalletError(
                f"Unsupported DID method for askar storage: {method.method_name}"
            )

        try:
            keypair = create_keypair(key_type, seed)
            verkey_bytes = keypair.get_public_bytes()
            verkey = bytes_to_b58(verkey_bytes)

            try:
                await self._session.handle.insert_key(
                    verkey, keypair, metadata=json.dumps(metadata)
                )
            except AskarError as err:
                if err.code == AskarErrorCode.DUPLICATE:
                    # update metadata?
                    pass
                else:
                    raise WalletError("Error inserting key") from err

            if method == DIDMethod.KEY:
                did = DIDKey.from_public_key(verkey_bytes, key_type).did
            elif not did:
                did = bytes_to_b58(verkey_bytes[:16])

            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if item:
                did_info = item.value_json
                if did_info.get("verkey") != verkey:
                    raise WalletDuplicateError("DID already present in wallet")
                if did_info.get("metadata") != metadata:
                    did_info["metadata"] = metadata
                    await self._session.handle.replace(
                        CATEGORY_DID, did, value_json=did_info, tags=item.tags
                    )
            else:
                await self._session.handle.insert(
                    CATEGORY_DID,
                    did,
                    value_json={
                        "did": did,
                        "method": method.method_name,
                        "verkey": verkey,
                        "verkey_type": key_type.key_type,
                        "metadata": metadata,
                    },
                    tags={
                        "method": method.method_name,
                        "verkey": verkey,
                        "verkey_type": key_type.key_type,
                    },
                )

        except AskarError as err:
            raise WalletError("Error when creating local DID") from err

        return DIDInfo(
            did=did, verkey=verkey, metadata=metadata, method=method, key_type=key_type
        )

    # FIXME implement get_public_did more efficiently (store lookup record)

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """
        Get list of defined local DIDs.

        Returns:
            A list of locally stored DIDs as `DIDInfo` instances

        """

        ret = []
        for item in await self._session.handle.fetch_all(CATEGORY_DID):
            ret.append(_load_did_entry(item))
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
            WalletError: If there is an aries_askar error

        """

        if not did:
            raise WalletNotFoundError("No identifier provided")
        try:
            did = await self._session.handle.fetch(CATEGORY_DID, did)
        except AskarError as err:
            raise WalletError("Error when fetching local DID") from err
        if not did:
            raise WalletNotFoundError("Unknown DID: {}".format(did))
        return _load_did_entry(did)

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

        try:
            dids = await self._session.handle.fetch_all(
                CATEGORY_DID, {"verkey": verkey}, limit=1
            )
        except AskarError as err:
            raise WalletError("Error when fetching local DID for verkey") from err
        if dids:
            return _load_did_entry(dids[0])
        raise WalletNotFoundError("No DID defined for verkey: {}".format(verkey))

    async def replace_local_did_metadata(self, did: str, metadata: dict):
        """
        Replace metadata for a local DID.

        Args:
            did: The DID for which to replace metadata
            metadata: The new metadata

        """

        try:
            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if not item:
                raise WalletNotFoundError("Unknown DID: {}".format(did)) from None
            entry_val = item.value_json
            if entry_val["metadata"] != metadata:
                entry_val["metadata"] = metadata
                await self._session.handle.replace(
                    CATEGORY_DID, did, value_json=entry_val, tags=item.tags
                )
        except AskarError as err:
            raise WalletError("Error updating DID metadata") from err

    async def set_did_endpoint(
        self,
        did: str,
        endpoint: str,
        ledger: BaseLedger,
        endpoint_type: EndpointType = None,
    ):
        """
        Update the endpoint for a DID in the wallet, send to ledger if public or posted.

        Args:
            did: DID for which to set endpoint
            endpoint: the endpoint to set, None to clear
            ledger: the ledger to which to send endpoint update if
                DID is public or posted
            endpoint_type: the type of the endpoint/service. Only endpoint_type
                'endpoint' affects local wallet
        """
        did_info = await self.get_local_did(did)
        if did_info.method != DIDMethod.SOV:
            raise WalletError("Setting DID endpoint is only allowed for did:sov DIDs")
        metadata = {**did_info.metadata}
        if not endpoint_type:
            endpoint_type = EndpointType.ENDPOINT
        if endpoint_type == EndpointType.ENDPOINT:
            metadata[endpoint_type.indy] = endpoint

        wallet_public_didinfo = await self.get_public_did()
        if (
            wallet_public_didinfo and wallet_public_didinfo.did == did
        ) or did_info.metadata.get("posted"):
            # if DID on ledger, set endpoint there first
            if not ledger:
                raise LedgerConfigError(
                    f"No ledger available but DID {did} is public: missing wallet-type?"
                )
            if not ledger.read_only:
                async with ledger:
                    await ledger.update_endpoint_for_did(did, endpoint, endpoint_type)

        await self.replace_local_did_metadata(did, metadata)

    async def rotate_did_keypair_start(self, did: str, next_seed: str = None) -> str:
        """
        Begin key rotation for DID that wallet owns: generate new keypair.

        Args:
            did: signing DID
            next_seed: incoming replacement seed (default random)

        Returns:
            The new verification key

        """
        # Check if DID can rotate keys
        did_method = DIDMethod.from_did(did)
        if not did_method.supports_rotation:
            raise WalletError(
                f"DID method '{did_method.method_name}' does not support key rotation."
            )

        # create a new key to be rotated to (only did:sov/ED25519 supported for now)
        keypair = create_keypair(KeyType.ED25519, next_seed)
        verkey = bytes_to_b58(keypair.get_public_bytes())
        try:
            await self._session.handle.insert_key(
                verkey,
                keypair,
            )
        except AskarError as err:
            if err.code == AskarErrorCode.DUPLICATE:
                pass
            else:
                raise WalletError(
                    "Error when creating new keypair for local DID"
                ) from err

        try:
            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if not item:
                raise WalletNotFoundError("Unknown DID: {}".format(did)) from None
            entry_val = item.value_json
            metadata = entry_val.get("metadata", {})
            metadata["next_verkey"] = verkey
            entry_val["metadata"] = metadata
            await self._session.handle.replace(
                CATEGORY_DID, did, value_json=entry_val, tags=item.tags
            )
        except AskarError as err:
            raise WalletError("Error updating DID metadata") from err

        return verkey

    async def rotate_did_keypair_apply(self, did: str) -> DIDInfo:
        """
        Apply temporary keypair as main for DID that wallet owns.

        Args:
            did: signing DID

        Returns:
            DIDInfo with new verification key and metadata for DID

        """
        try:
            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if not item:
                raise WalletNotFoundError("Unknown DID: {}".format(did)) from None
            entry_val = item.value_json
            metadata = entry_val.get("metadata", {})
            next_verkey = metadata.get("next_verkey")
            if not next_verkey:
                raise WalletError("Cannot rotate DID key: no next key established")
            del metadata["next_verkey"]
            entry_val["verkey"] = next_verkey
            item.tags["verkey"] = next_verkey
            await self._session.handle.replace(
                CATEGORY_DID, did, value_json=entry_val, tags=item.tags
            )
        except AskarError as err:
            raise WalletError("Error updating DID metadata") from err

    async def sign_message(
        self, message: Union[List[bytes], bytes], from_verkey: str
    ) -> bytes:
        """
        Sign message(s) using the private key associated with a given verkey.

        Args:
            message: The message(s) to sign
            from_verkey: Sign using the private key related to this verkey

        Returns:
            A signature

        Raises:
            WalletError: If the message is not provided
            WalletError: If the verkey is not provided
            WalletError: If an aries_askar error occurs

        """
        if not message:
            raise WalletError("Message not provided")
        if not from_verkey:
            raise WalletError("Verkey not provided")
        try:
            keypair = await self._session.handle.fetch_key(from_verkey)
            if not keypair:
                raise WalletNotFoundError("Missing key for sign operation")
            key = keypair.key
            if key.algorithm == KeyAlg.BLS12_381_G2:
                # for now - must extract the key and use sign_message
                return sign_message(
                    message=message,
                    secret=key.get_secret_bytes(),
                    key_type=KeyType.BLS12381G2,
                )

            else:
                return key.sign_message(message)
        except AskarError as err:
            raise WalletError("Exception when signing message") from err

    async def verify_message(
        self,
        message: Union[List[bytes], bytes],
        signature: bytes,
        from_verkey: str,
        key_type: KeyType,
    ) -> bool:
        """
        Verify a signature against the public key of the signer.

        Args:
            message: The message to verify
            signature: The signature to verify
            from_verkey: Verkey to use in verification
            key_type: The key type to derive the signature verification algorithm from

        Returns:
            True if verified, else False

        Raises:
            WalletError: If the verkey is not provided
            WalletError: If the signature is not provided
            WalletError: If the message is not provided
            WalletError: If an aries_askar error occurs

        """
        if not from_verkey:
            raise WalletError("Verkey not provided")
        if not signature:
            raise WalletError("Signature not provided")
        if not message:
            raise WalletError("Message not provided")

        verkey = b58_to_bytes(from_verkey)

        if key_type == KeyType.ED25519:
            try:
                pk = Key.from_public_bytes(KeyAlg.ED25519, verkey)
                return pk.verify_signature(message, signature)
            except AskarError as err:
                raise WalletError("Exception when verifying message signature") from err

        # other key types are currently verified outside of Askar
        return verify_signed_message(
            message=message,
            signature=signature,
            verkey=verkey,
            key_type=key_type,
        )

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
            WalletError: If no message is provided
            WalletError: If an aries_askar error occurs

        """
        if message is None:
            raise WalletError("Message not provided")
        try:
            if from_verkey:
                from_key_entry = await self._session.handle.fetch_key(from_verkey)
                if not from_key_entry:
                    raise WalletNotFoundError("Missing key for pack operation")
                from_key = from_key_entry.key
            else:
                from_key = None
            return await asyncio.get_event_loop().run_in_executor(
                None, pack_message, to_verkeys, from_key, message
            )
        except AskarError as err:
            raise WalletError("Exception when packing message") from err

    async def unpack_message(self, enc_message: bytes) -> Tuple[str, str, str]:
        """
        Unpack a message.

        Args:
            enc_message: The packed message bytes

        Returns:
            A tuple: (message, from_verkey, to_verkey)

        Raises:
            WalletError: If the message is not provided
            WalletError: If an aries_askar error occurs

        """
        if not enc_message:
            raise WalletError("Message not provided")
        try:
            (
                unpacked_json,
                recipient,
                sender,
            ) = await unpack_message(self._session.handle, enc_message)
        except AskarError as err:
            raise WalletError("Exception when unpacking message") from err
        return unpacked_json.decode("utf-8"), sender, recipient


def pack_message(
    to_verkeys: Sequence[str], from_key: Optional[Key], message: bytes
) -> bytes:
    wrapper = JweEnvelope()
    cek = Key.generate(KeyAlg.C20P)
    # avoid converting to bytes object: this way the only copy is zeroed afterward
    cek_b = key_get_secret_bytes(cek._handle)
    sender_vk = (
        bytes_to_b58(from_key.get_public_bytes()).encode("utf-8") if from_key else None
    )
    sender_xk = from_key.convert_key(KeyAlg.X25519) if from_key else None

    for target_vk in to_verkeys:
        target_xk = Key.from_public_bytes(
            KeyAlg.ED25519, b58_to_bytes(target_vk)
        ).convert_key(KeyAlg.X25519)
        if sender_vk:
            enc_sender = crypto_box_seal(target_xk, sender_vk)
            nonce = crypto_box_random_nonce()
            enc_cek = crypto_box(target_xk, sender_xk, cek_b, nonce)
            wrapper.add_recipient(
                JweRecipient(
                    encrypted_key=enc_cek,
                    header=OrderedDict(
                        [
                            ("kid", target_vk),
                            ("sender", b64url(enc_sender)),
                            ("iv", b64url(nonce)),
                        ]
                    ),
                )
            )
        else:
            enc_sender = None
            nonce = None
            enc_cek = crypto_box_seal(target_xk, cek_b)
            wrapper.add_recipient(
                JweRecipient(encrypted_key=enc_cek, header={"kid": target_vk})
            )
    wrapper.set_protected(
        OrderedDict(
            [
                ("enc", "xchacha20poly1305_ietf"),
                ("typ", "JWM/1.0"),
                ("alg", "Authcrypt" if from_key else "Anoncrypt"),
            ]
        ),
        auto_flatten=False,
    )
    nonce = cek.aead_random_nonce()
    ciphertext = cek.aead_encrypt(message, nonce, wrapper.protected_bytes)
    tag = ciphertext[-16:]
    ciphertext = ciphertext[:-16]
    wrapper.set_payload(ciphertext, nonce, tag)
    return wrapper.to_json().encode("utf-8")


async def unpack_message(session: Session, enc_message: bytes) -> Tuple[str, str, str]:
    try:
        wrapper = JweEnvelope.from_json(enc_message)
    except ValidationError:
        raise WalletError("Invalid packed message")

    alg = wrapper.protected.get("alg")
    is_authcrypt = alg == "Authcrypt"
    if not is_authcrypt and alg != "Anoncrypt":
        raise WalletError("Unsupported pack algorithm: {}".format(alg))

    recips = extract_pack_recipients(wrapper.recipients())

    payload_key, sender_vk = None, None
    for recip_vk in recips:
        recip_key_entry = await session.fetch_key(recip_vk)
        if recip_key_entry:
            payload_key, sender_vk = extract_payload_key(
                recips[recip_vk], recip_key_entry.key
            )
            break

    if not payload_key:
        raise WalletError(
            "No corresponding recipient key found in {}".format(tuple(recips))
        )
    if not sender_vk and is_authcrypt:
        raise WalletError("Sender public key not provided for Authcrypt message")

    cek = Key.from_secret_bytes(KeyAlg.C20P, payload_key)
    ciphertext = wrapper.ciphertext + wrapper.tag
    message = cek.aead_decrypt(ciphertext, wrapper.iv, wrapper.protected_bytes)
    return message, recip_vk, sender_vk


def extract_payload_key(sender_cek: dict, recip_secret: Key) -> Tuple[bytes, str]:
    """
    Extract the payload key from pack recipient details.

    Returns: A tuple of the CEK and sender verkey
    """
    recip_x = recip_secret.convert_key(KeyAlg.X25519)

    if sender_cek["nonce"] and sender_cek["sender"]:
        sender_vk = crypto_box_seal_open(recip_x, sender_cek["sender"]).decode("utf-8")
        sender_x = Key.from_public_bytes(
            KeyAlg.ED25519, b58_to_bytes(sender_vk)
        ).convert_key(KeyAlg.X25519)
        cek = crypto_box_open(recip_x, sender_x, sender_cek["key"], sender_cek["nonce"])
    else:
        sender_vk = None
        cek = crypto_box_seal_open(recip_x, sender_cek["key"])
    return cek, sender_vk
