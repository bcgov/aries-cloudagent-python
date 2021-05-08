from unittest import TestCase

from ..cred import IndyAttrValue, IndyCredential
from ..cred_abstract import IndyCredAbstract, IndyKeyCorrectnessProof
from ..cred_request import IndyCredRequest

KC_PROOF = {
    "c": "123467890",
    "xz_cap": "12345678901234567890",
    "xr_cap": [
        [
            "remainder",
            "1234567890",
        ],
        [
            "number",
            "12345678901234",
        ],
        [
            "master_secret",
            "12345678901234",
        ],
    ],
}

TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "bc-reg"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:default"


class TestIndyKeyCorrectnessProof(TestCase):
    """Indy key correctness proof tests"""

    def test_serde(self):
        """Test de/serialization."""
        kcp = IndyKeyCorrectnessProof.deserialize(KC_PROOF)
        assert type(kcp) == IndyKeyCorrectnessProof

        kcp_dict = kcp.serialize()
        assert kcp_dict == KC_PROOF


class TestIndyCredAbstract(TestCase):
    """Indy cred abstract tests."""

    def test_serde(self):
        """Test de/serialization."""
        obj = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "nonce": "1234567890",
            "key_correctness_proof": KC_PROOF,
        }
        cred_abstract = IndyCredAbstract.deserialize(obj)
        assert type(cred_abstract) == IndyCredAbstract

        cred_abstract_dict = cred_abstract.serialize()
        assert cred_abstract_dict == obj


class TestIndyCredRequest(TestCase):
    """Indy cred request tests."""

    def test_serde(self):
        """Test de/serialization."""
        obj = {
            "prover_did": f"did:sov:{TEST_DID}",
            "cred_def_id": CRED_DEF_ID,
            "blinded_ms": {"...": "..."},
            "blinded_ms_correctness_proof": {"...": "..."},
            "nonce": "1234567890",
        }
        cred_request = IndyCredRequest.deserialize(obj)
        assert type(cred_request) == IndyCredRequest

        cred_request_dict = cred_request.serialize()
        assert cred_request_dict == obj


class TestIndyAttrValue(TestCase):
    """Indy attr value tests."""

    def test_serde(self):
        """Test de/serialization."""
        obj = {
            "raw": "test",
            "encoded": "1234567890",
        }
        attr_val = IndyAttrValue.deserialize(obj)
        assert type(attr_val) == IndyAttrValue

        attr_val_dict = attr_val.serialize()
        assert attr_val_dict == obj


class TestIndyCredential(TestCase):
    """Indy credential tests."""

    def test_serde(self):
        """Test de/serialization."""
        obj = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "rev_reg_id": None,
            "values": {
                "busId": {
                    "raw": "12345",
                    "encoded": "12345",
                },
                "legalName": {
                    "raw": "Muffin Moon",
                    "encoded": "13419834198651328645901659586128164",
                },
            },
            "signature": {"...": "..."},
            "signature_correctness_proof": {"...": "..."},
            "rev_reg": None,
            "witness": None,
        }
        cred = IndyCredential.deserialize(obj)
        assert type(cred) == IndyCredential

        cred_dict = cred.serialize()
        assert cred_dict.items() <= obj.items()
