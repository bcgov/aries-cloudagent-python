"""Cryptography functions used by BasicWallet."""

import logging
import re
from collections import OrderedDict
from typing import Callable, List, Optional, Sequence, Tuple, Union

import nacl.bindings
import nacl.exceptions
import nacl.utils
from marshmallow import ValidationError

from ..utils.jwe import JweEnvelope, JweRecipient, b64url, from_b64url
from .bbs import (
    BbsException,
    create_bls12381g2_keypair,
    sign_messages_bls12381g2,
    verify_signed_messages_bls12381g2,
)
from .error import WalletError
from .key_type import BLS12381G2, ED25519, KeyType
from .util import b58_to_bytes, b64_to_bytes, bytes_to_b58, random_seed

LOGGER = logging.getLogger(__name__)


def create_keypair(
    key_type: KeyType, seed: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Create a public and private keypair from a seed value.

    Args:
        key_type: The type of key to generate
        seed: Seed for keypair

    Raises:
        WalletError: If the key type is not supported

    Returns:
        A tuple of (public key, secret key)

    """
    if key_type == ED25519:
        return create_ed25519_keypair(seed)
    elif key_type == BLS12381G2:
        # This ensures python won't crash if bbs is not installed and not used

        return create_bls12381g2_keypair(seed)
    else:
        raise WalletError(f"Unsupported key type: {key_type.key_type}")


def create_ed25519_keypair(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Create a public and private ed25519 keypair from a seed value.

    Args:
        seed: Seed for keypair

    Returns:
        A tuple of (public key, secret key)

    """
    if not seed:
        seed = random_seed()
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return pk, sk


def seed_to_did(seed: str) -> str:
    """Derive a DID from a seed value.

    Args:
        seed: The seed to derive

    Returns:
        The DID derived from the seed

    """
    seed = validate_seed(seed)
    verkey, _ = create_ed25519_keypair(seed)
    did = bytes_to_b58(verkey[:16])
    return did


def did_is_self_certified(did: str, verkey: str) -> bool:
    """Check if the DID is self certified.

    Args:
        did: DID string
        verkey: VERKEY string
    """
    ABBREVIATED_VERKEY_REGEX = "^~[1-9A-HJ-NP-Za-km-z]{21,22}$"
    if re.search(ABBREVIATED_VERKEY_REGEX, verkey):
        return True
    verkey_bytes = b58_to_bytes(verkey)
    did_from_verkey = bytes_to_b58(verkey_bytes[:16])
    if did == did_from_verkey:
        return True
    return False


def sign_pk_from_sk(secret: bytes) -> bytes:
    """Extract the verkey from a secret signing key."""
    seed_len = nacl.bindings.crypto_sign_SEEDBYTES
    return secret[seed_len:]


def validate_seed(seed: Union[str, bytes, None]) -> bytes:
    """Convert a seed parameter to standard format and check length.

    Args:
        seed: The seed to validate

    Returns:
        The validated and encoded seed

    """
    if not seed:
        return None
    if isinstance(seed, str):
        if "=" in seed:
            seed = b64_to_bytes(seed)
        else:
            seed = seed.encode("ascii")
    if not isinstance(seed, bytes):
        raise WalletError("Seed value is not a string or bytes")
    if len(seed) != 32:
        raise WalletError("Seed value must be 32 bytes in length")
    return seed


def sign_message(
    message: Union[List[bytes], bytes], secret: bytes, key_type: KeyType
) -> bytes:
    """Sign message(s) using a private signing key.

    Args:
        message: The message(s) to sign
        secret: The private signing key
        key_type: The key type to derive the signature algorithm from

    Returns:
        bytes: The signature

    """
    # Make messages list if not already for easier checking going forward
    messages = message if isinstance(message, list) else [message]

    if key_type == ED25519:
        if len(messages) > 1:
            raise WalletError("ed25519 can only sign a single message")

        return sign_message_ed25519(
            message=messages[0],
            secret=secret,
        )
    elif key_type == BLS12381G2:
        return sign_messages_bls12381g2(messages=messages, secret=secret)
    else:
        raise WalletError(f"Unsupported key type: {key_type.key_type}")


def sign_message_ed25519(message: bytes, secret: bytes) -> bytes:
    """Sign message using an ed25519 private signing key.

    This function takes a message and a private signing key as input and returns the
    signature of the message using the ed25519 algorithm.

    Args:
        message (bytes): The message to sign.
        secret (bytes): The private signing key.

    Returns:
        bytes: The signature of the message.

    """
    result = nacl.bindings.crypto_sign(message, secret)
    sig = result[: nacl.bindings.crypto_sign_BYTES]
    return sig


def verify_signed_message(
    message: Union[List[bytes], bytes],
    signature: bytes,
    verkey: bytes,
    key_type: KeyType,
) -> bool:
    """Verify a signed message according to a public verification key.

    Args:
        message: The message(s) to verify
        signature: The signature to verify
        verkey: The verkey to use in verification
        key_type: The key type to derive the signature verification algorithm from

    Returns:
        True if verified, else False

    """
    # Make messages list if not already for easier checking going forward
    messages = message if isinstance(message, list) else [message]

    if key_type == ED25519:
        if len(messages) > 1:
            raise WalletError("ed25519 can only verify a single message")

        return verify_signed_message_ed25519(
            message=messages[0], signature=signature, verkey=verkey
        )
    elif key_type == BLS12381G2:
        try:
            return verify_signed_messages_bls12381g2(
                messages=messages, signature=signature, public_key=verkey
            )
        except BbsException as e:
            raise WalletError("Unable to verify message") from e
    else:
        raise WalletError(f"Unsupported key type: {key_type.key_type}")


def verify_signed_message_ed25519(
    message: bytes, signature: bytes, verkey: bytes
) -> bool:
    """Verify an ed25519 signed message according to a public verification key.

    Args:
        message: The message to verify
        signature: The signature to verify
        verkey: The verkey to use in verification

    Returns:
        True if verified, else False

    """
    try:
        nacl.bindings.crypto_sign_open(signature + message, verkey)
    except nacl.exceptions.BadSignatureError:
        return False
    return True


def add_pack_recipients(
    wrapper: JweEnvelope,
    cek: bytes,
    to_verkeys: Sequence[bytes],
    from_secret: Optional[bytes] = None,
):
    """Assemble the recipients block of a packed message.

    Args:
        wrapper: The envelope to add recipients to
        cek: The content encryption key
        to_verkeys: Verkeys of recipients
        from_secret: Secret to use for signing keys

    Returns:
        A tuple of (json result, key)

    """
    for target_vk in to_verkeys:
        target_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(target_vk)
        if from_secret:
            sender_pk = sign_pk_from_sk(from_secret)
            sender_vk = bytes_to_b58(sender_pk).encode("utf-8")
            enc_sender = nacl.bindings.crypto_box_seal(sender_vk, target_pk)
            sk = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(from_secret)

            nonce = nacl.utils.random(nacl.bindings.crypto_box_NONCEBYTES)
            enc_cek = nacl.bindings.crypto_box(cek, nonce, target_pk, sk)
            wrapper.add_recipient(
                JweRecipient(
                    encrypted_key=enc_cek,
                    header=OrderedDict(
                        [
                            ("kid", bytes_to_b58(target_vk)),
                            ("sender", b64url(enc_sender)),
                            ("iv", b64url(nonce)),
                        ]
                    ),
                )
            )
        else:
            enc_sender = None
            nonce = None
            enc_cek = nacl.bindings.crypto_box_seal(cek, target_pk)
            wrapper.add_recipient(
                JweRecipient(
                    encrypted_key=enc_cek, header={"kid": bytes_to_b58(target_vk)}
                )
            )


def ed25519_pk_to_curve25519(public_key: bytes) -> bytes:
    """Covert a public Ed25519 key to a public Curve25519 key as bytes."""
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(public_key)


def encrypt_plaintext(
    message: str, add_data: bytes, key: bytes
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt the payload of a packed message.

    Args:
        message (str): The message to encrypt.
        add_data (bytes): Additional data to include in the encryption.
        key (bytes): The key used for encryption.

    Returns:
        Tuple[bytes, bytes, bytes]: A tuple containing the ciphertext, nonce, and tag.

    """
    nonce = nacl.utils.random(nacl.bindings.crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
    message_bin = message.encode("utf-8")
    output = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        message_bin, add_data, nonce, key
    )
    mlen = len(message)
    ciphertext = output[:mlen]
    tag = output[mlen:]
    return ciphertext, nonce, tag


def decrypt_plaintext(
    ciphertext: bytes, recips_bin: bytes, nonce: bytes, key: bytes
) -> str:
    """Decrypt the payload of a packed message.

    Args:
        ciphertext (bytes): The encrypted payload to be decrypted.
        recips_bin (bytes): The binary representation of the recipients' public keys.
        nonce (bytes): The nonce used for encryption.
        key (bytes): The secret key used for encryption.

    Returns:
        str: The decrypted string.

    """
    output = nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
        ciphertext, recips_bin, nonce, key
    )
    return output.decode("utf-8")


def encode_pack_message(
    message: str, to_verkeys: Sequence[bytes], from_secret: Optional[bytes] = None
) -> bytes:
    """Assemble a packed message for a set of recipients, optionally including the sender.

    Args:
        message: The message to pack
        to_verkeys: The verkeys to pack the message for
        from_secret: The sender secret

    Returns:
        The encoded message

    """
    wrapper = JweEnvelope(with_protected_recipients=True, with_flatten_recipients=False)
    cek = nacl.bindings.crypto_secretstream_xchacha20poly1305_keygen()
    add_pack_recipients(wrapper, cek, to_verkeys, from_secret)
    wrapper.set_protected(
        OrderedDict(
            [
                ("enc", "xchacha20poly1305_ietf"),
                ("typ", "JWM/1.0"),
                ("alg", "Authcrypt" if from_secret else "Anoncrypt"),
            ]
        ),
    )
    ciphertext, nonce, tag = encrypt_plaintext(message, wrapper.protected_bytes, cek)
    wrapper.set_payload(ciphertext, nonce, tag)
    return wrapper.to_json().encode("utf-8")


def decode_pack_message(
    enc_message: bytes, find_key: Callable
) -> Tuple[str, Optional[str], str]:
    """Decode a packed message.

    Disassemble and unencrypt a packed message, returning the message content,
    verification key of the sender (if available), and verification key of the
    recipient.

    Args:
        enc_message: The encrypted message
        find_key: Function to retrieve private key

    Returns:
        A tuple of (message, sender_vk, recip_vk)

    Raises:
        ValueError: If the packed message is invalid
        ValueError: If the packed message recipients are invalid
        ValueError: If the pack algorithm is unsupported
        ValueError: If the sender's public key was not provided

    """
    wrapper, recips, is_authcrypt = decode_pack_message_outer(enc_message)
    payload_key, sender_vk = None, None
    for recip_vk in recips:
        recip_secret = find_key(recip_vk)
        if recip_secret:
            payload_key, sender_vk = extract_payload_key(recips[recip_vk], recip_secret)
            break

    if not payload_key:
        raise ValueError(
            "No corresponding recipient key found in {}".format(tuple(recips))
        )
    if not sender_vk and is_authcrypt:
        raise ValueError("Sender public key not provided for Authcrypt message")

    message = decode_pack_message_payload(wrapper, payload_key)
    return message, sender_vk, recip_vk


def decode_pack_message_outer(enc_message: bytes) -> Tuple[dict, dict, bool]:
    """Decode the outer wrapper of a packed message and extract the recipients.

    Args:
        enc_message: The encrypted message

    Returns: a tuple of the decoded wrapper, recipients, and authcrypt flag

    """
    try:
        wrapper = JweEnvelope.from_json(enc_message)
    except ValidationError as err:
        LOGGER.error(err)
        raise ValueError("Invalid packed message")

    alg = wrapper.protected.get("alg")
    is_authcrypt = alg == "Authcrypt"
    if not is_authcrypt and alg != "Anoncrypt":
        raise ValueError("Unsupported pack algorithm: {}".format(alg))

    recips = extract_pack_recipients(wrapper.recipients)
    return wrapper, recips, is_authcrypt


def decode_pack_message_payload(wrapper: JweEnvelope, payload_key: bytes) -> str:
    """Decode the payload of a packed message once the CEK is known.

    Args:
        wrapper: The decoded message wrapper
        payload_key: The decrypted payload key

    """
    payload_bin = wrapper.ciphertext + wrapper.tag
    message = decrypt_plaintext(
        payload_bin, wrapper.protected_bytes, wrapper.iv, payload_key
    )
    return message


def extract_pack_recipients(recipients: Sequence[JweRecipient]) -> dict:
    """Extract the pack message recipients into a dict indexed by verkey.

    Args:
        recipients: Recipients to locate

    Raises:
        ValueError: If the recipients block is mal-formatted

    """
    result = {}
    for recip in recipients:
        recip_vk_b58 = recip.header.get("kid")
        if not recip_vk_b58:
            raise ValueError("Blank recipient key")
        if recip_vk_b58 in result:
            raise ValueError("Duplicate recipient key")

        sender_b64 = recip.header.get("sender")
        enc_sender = from_b64url(sender_b64) if sender_b64 else None

        nonce_b64 = recip.header.get("iv")
        if sender_b64 and not nonce_b64:
            raise ValueError("Missing iv")
        elif not sender_b64 and nonce_b64:
            raise ValueError("Unexpected iv")
        nonce = from_b64url(nonce_b64) if nonce_b64 else None

        result[recip_vk_b58] = {
            "sender": enc_sender,
            "nonce": nonce,
            "key": recip.encrypted_key,
        }
    return result


def extract_payload_key(sender_cek: dict, recip_secret: bytes) -> Tuple[bytes, str]:
    """Extract the payload key from pack recipient details.

    Returns: A tuple of the CEK and sender verkey
    """
    recip_vk = sign_pk_from_sk(recip_secret)
    recip_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(recip_vk)
    recip_sk = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(recip_secret)

    if sender_cek["nonce"] and sender_cek["sender"]:
        sender_vk_bin = nacl.bindings.crypto_box_seal_open(
            sender_cek["sender"], recip_pk, recip_sk
        )
        sender_vk = sender_vk_bin.decode("utf-8")
        sender_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(
            b58_to_bytes(sender_vk_bin)
        )
        cek = nacl.bindings.crypto_box_open(
            sender_cek["key"], sender_cek["nonce"], sender_pk, recip_sk
        )
    else:
        sender_vk = None
        cek = nacl.bindings.crypto_box_seal_open(sender_cek["key"], recip_pk, recip_sk)
    return cek, sender_vk
