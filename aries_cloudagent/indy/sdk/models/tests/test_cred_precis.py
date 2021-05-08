from unittest import TestCase

from ..cred_precis import IndyCredInfo, IndyCredInfoSchema

TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "preferences"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:default"
REV_REG_ID = f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:0"

CRED_INFO = {
    "referent": "abc123",
    "attrs": {
        "userid": "alice",
        "dob": "2000-01-01",
        "favourite_colour": "purple",
    },
    "schema_id": SCHEMA_ID,
    "cred_def_id": CRED_DEF_ID,
    "rev_reg_id": REV_REG_ID,
    "cred_rev_id": "1",
}


class TestCredInfo(TestCase):
    """Indy cred info tests"""

    def test_serde(self):
        """Test de/serialization."""
        cred_info = IndyCredInfo.deserialize(CRED_INFO)
        assert type(cred_info) == IndyCredInfo

        ser = cred_info.serialize()
        assert ser == CRED_INFO

        deser = IndyCredInfo.deserialize(ser)
        reser = deser.serialize()
        assert ser == reser

        obj = IndyCredInfo(**CRED_INFO)
        ser = obj.serialize()
        assert ser == reser
