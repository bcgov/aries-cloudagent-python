from unittest import TestCase

from ..non_rev_interval import IndyNonRevocationInterval
from ..proof_request import IndyProofRequest

TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "preferences"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:default"
REV_REG_ID = f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:0"

PROOF_REQ = {
    "nonce": "123432421212",
    "name": "proof_req_1",
    "version": "0.1",
    "requested_attributes": {
        "attr1_referent": {
            "name": "name",
            "restrictions": [
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": TEST_DID,
                    "schema_name": SCHEMA_NAME,
                    "schema_version": "1.0",
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                }
            ],
            "non_revoked": {  # overrides proof-level spec
                "from": 1234567890,
                "to": 1234567890,
            },
        }
    },
    "requested_predicates": {
        "predicate1_referent": {
            "name": "age",
            "p_type": ">=",
            "p_value": 18,
            "restrictions": [
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": TEST_DID,
                    "schema_name": SCHEMA_NAME,
                    "schema_version": "1.0",
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                }
            ],
            "non_revoked": {  # overrides proof-level spec
                "from": 1234567890,
                "to": 1234567890,
            },
        }
    },
    "non_revoked": {"from": 1584704048, "to": 1584704048},
}


class TestIndyProofReq(TestCase):
    """Test indy proof req."""

    def test_serde(self):
        """Test de/serialization."""

        proof_req = IndyProofRequest.deserialize(PROOF_REQ)
        assert type(proof_req) == IndyProofRequest

        ser = proof_req.serialize()
        assert ser == PROOF_REQ

        deser = IndyProofRequest.deserialize(ser)
        reser = deser.serialize()
        assert ser == reser

        obj = IndyProofRequest(**PROOF_REQ)
        ser = obj.serialize()
        assert ser == reser

        obj2 = IndyProofRequest(
            nonce=obj.nonce,
            name=obj.name,
            version=obj.version,
            requested_attributes=obj.requested_attributes,
            requested_predicates=obj.requested_predicates,
            non_revoked=obj.non_revoked,
        )
        assert ser.items() <= obj2.serialize().items()
