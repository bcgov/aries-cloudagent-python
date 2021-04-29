import pytest
import json

from unittest import mock, TestCase

from ..key_type import KeyType
from ..error import WalletError
from ...utils.jwe import JweRecipient
from ..util import str_to_b64
from .. import crypto as test_module

SEED_B64 = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
SEED = "00000000000000000000000000000000"
MESSAGE = b"Hello World"


class TestCrypto(TestCase):
    def test_validate_seed(self):
        assert test_module.validate_seed(None) is None

        assert SEED.encode("ascii") == test_module.validate_seed(SEED_B64)
        assert SEED.encode("ascii") == test_module.validate_seed(SEED)

        with pytest.raises(test_module.WalletError) as excinfo:
            test_module.validate_seed({"bad": "seed"})
        assert "value is not a string or bytes" in str(excinfo.value)

        with pytest.raises(test_module.WalletError) as excinfo:
            test_module.validate_seed(f"{SEED}{SEED}")
        assert "value must be 32 bytes in length" in str(excinfo.value)

    def test_seeds_keys(self):
        assert len(test_module.seed_to_did(SEED)) in (22, 23)

        (public_key, secret_key) = test_module.create_keypair(
            test_module.KeyType.ED25519
        )
        assert public_key
        assert secret_key

        assert test_module.sign_pk_from_sk(secret_key) in secret_key

    def test_decode_pack_message_x(self):
        with mock.patch.object(
            test_module, "decode_pack_message_outer", mock.MagicMock()
        ) as mock_decode_outer, mock.patch.object(
            test_module, "extract_payload_key", mock.MagicMock()
        ) as mock_extract:
            mock_decode_outer.return_value = (b"wrapper", {"my": b"recip"}, True)

            with pytest.raises(ValueError) as excinfo:
                test_module.decode_pack_message(b"encrypted", lambda x: None)
            assert "No corresponding recipient key found" in str(excinfo.value)

            mock_extract.return_value = (b"payload_key", None)
            with pytest.raises(ValueError) as excinfo:
                test_module.decode_pack_message(b"encrypted", lambda x: b"recip_secret")
            assert "Sender public key not provided" in str(excinfo.value)

    def test_decode_pack_message_outer_x(self):
        with pytest.raises(ValueError) as excinfo:
            test_module.decode_pack_message_outer(json.dumps({"invalid": "content"}))
        assert "Invalid packed message" == str(excinfo.value)

        recips = str_to_b64(
            json.dumps(
                {
                    "enc": "xchacha20poly1305_ietf",
                    "typ": "JWM/1.0",
                    "alg": "Quadruple rot-13",
                    "recipients": "not a list",
                }
            )
        )
        with pytest.raises(ValueError) as excinfo:
            test_module.decode_pack_message_outer(
                json.dumps(
                    {
                        "protected": recips,
                        "iv": "00000000",
                        "tag": "tag",
                        "ciphertext": "secret",
                    }
                )
            )
        assert "Invalid packed message" == str(excinfo.value)

        recips = str_to_b64(
            json.dumps(
                {
                    "enc": "xchacha20poly1305_ietf",
                    "typ": "JWM/1.0",
                    "alg": "Quadruple rot-13",
                    "recipients": [],
                }
            )
        )
        with pytest.raises(ValueError) as excinfo:
            test_module.decode_pack_message_outer(
                json.dumps(
                    {
                        "protected": recips,
                        "iv": "00000000",
                        "tag": "tag",
                        "ciphertext": "secret",
                    }
                )
            )
        assert "Unsupported pack algorithm" in str(excinfo.value)

    def test_extract_pack_recipients_x(self):
        with pytest.raises(ValueError) as excinfo:
            test_module.extract_pack_recipients([JweRecipient(encrypted_key=b"")])
        assert "Blank recipient key" in str(excinfo.value)

        with pytest.raises(ValueError) as excinfo:
            test_module.extract_pack_recipients(
                [JweRecipient(encrypted_key=b"0000", header={"kid": "4mZ5TYv4oN"})] * 2
            )
        assert "Duplicate recipient key" in str(excinfo.value)

        with pytest.raises(ValueError) as excinfo:
            test_module.extract_pack_recipients(
                [
                    JweRecipient(
                        encrypted_key=b"0000",
                        header={"kid": "4mZ5TYv4oN", "sender": "4mZ5TYv4oN"},
                    )
                ]
            )
        assert "Missing iv" in str(excinfo.value)

        with pytest.raises(ValueError) as excinfo:
            test_module.extract_pack_recipients(
                [
                    JweRecipient(
                        encrypted_key=b"0000",
                        header={"kid": "4mZ5TYv4oN", "iv": "00000000"},
                    )
                ]
            )
        assert "Unexpected iv" in str(excinfo.value)

    def test_sign_ed25519_x_multiple_messages(self):
        with self.assertRaises(WalletError) as context:
            test_module.sign_message(
                [b"message1", b"message2"], b"secret", KeyType.ED25519
            )
        assert "ed25519 can only sign a single message" in str(context.exception)

    def test_sign_x_unsupported_key_type(self):
        with self.assertRaises(WalletError) as context:
            test_module.sign_message(
                [b"message1", b"message2"], b"secret", KeyType.BLS12381G1
            )
        assert "Unsupported key type: bls12381g1" in str(context.exception)

    def test_verify_ed25519_x_multiple_messages(self):
        with self.assertRaises(WalletError) as context:
            test_module.verify_signed_message(
                [b"message1", b"message2"], b"signature", b"verkey", KeyType.ED25519
            )
        assert "ed25519 can only verify a single message" in str(context.exception)

    def test_verify_x_unsupported_key_type(self):
        with self.assertRaises(WalletError) as context:
            test_module.verify_signed_message(
                [b"message1", b"message2"], b"signature", b"verkey", KeyType.BLS12381G1
            )
        assert "Unsupported key type: bls12381g1" in str(context.exception)
