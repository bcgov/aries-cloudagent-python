import pytest
import json

from asynctest import mock as async_mock
from asynctest import TestCase as AsyncTestCase
from copy import deepcopy
from time import time
from unittest import TestCase
from uuid import uuid4

from .....messaging.models.base import BaseModelError
from .....storage.vc_holder.vc_record import VCRecord

from ..pres_exch import (
    ClaimFormat,
    SubmissionRequirements,
    Holder,
    Filter,
    Constraints,
)


class TestPresExchSchemas(TestCase):
    """Presentation predicate specification tests"""

    def test_claim_format(self):
        submission_req_json = """
            {
                "jwt": {
                "alg": ["EdDSA", "ES256K", "ES384"]
                },
                "jwt_vc": {
                "alg": ["ES256K", "ES384"]
                },
                "jwt_vp": {
                "alg": ["EdDSA", "ES256K"]
                },
                "ldp_vc": {
                "proof_type": [
                    "JsonWebSignature2020",
                    "Ed25519Signature2018",
                    "EcdsaSecp256k1Signature2019",
                    "RsaSignature2018"
                ]
                },
                "ldp_vp": {
                "proof_type": ["Ed25519Signature2018"]
                },
                "ldp": {
                "proof_type": ["RsaSignature2018"]
                }
            }
        """
        expected_result = json.loads(submission_req_json)
        actual_result = (ClaimFormat.deserialize(submission_req_json)).serialize()
        assert expected_result == actual_result

    def test_submission_requirements_from(self):
        claim_format_json = """
            {
                "name": "European Union Citizenship Proofs",
                "rule": "pick",
                "min": 1,
                "from": "A"
            }
        """
        expected_result = json.loads(claim_format_json)
        actual_result = (
            SubmissionRequirements.deserialize(claim_format_json)
        ).serialize()
        assert expected_result == actual_result

    def test_submission_requirements_from_nested(self):
        nested_submission_req_json = """
            {
                "name": "Citizenship Information",
                "rule": "pick",
                "count": 1,
                "from_nested": [
                    {
                    "name": "United States Citizenship Proofs",
                    "purpose": "We need you to prove you are a US citizen.",
                    "rule": "all",
                    "from": "A"
                    },
                    {
                    "name": "European Union Citizenship Proofs",
                    "purpose": "We need you to prove you are a citizen of a EU country.",
                    "rule": "all",
                    "from": "B"
                    }
                ]
            }
        """
        expected_result = json.loads(nested_submission_req_json)
        actual_result = (
            SubmissionRequirements.deserialize(nested_submission_req_json)
        ).serialize()
        assert expected_result == actual_result

    def test_submission_requirements_from_missing(self):
        test_json = """
            {
                "name": "Citizenship Information",
                "rule": "pick",
                "count": 1
            }
        """
        with self.assertRaises(BaseModelError) as cm:
            (SubmissionRequirements.deserialize(test_json)).serialize()

    def test_submission_requirements_from_both_present(self):
        test_json = """
            {
                "name": "Citizenship Information",
                "rule": "pick",
                "count": 1,
                "from": "A",
                "from_nested": [
                    {
                    "name": "United States Citizenship Proofs",
                    "purpose": "We need you to prove you are a US citizen.",
                    "rule": "all",
                    "from": "A"
                    },
                    {
                    "name": "European Union Citizenship Proofs",
                    "purpose": "We need you to prove you are a citizen of a EU country.",
                    "rule": "all",
                    "from": "B"
                    }
                ]
            }
        """
        with self.assertRaises(BaseModelError) as cm:
            (SubmissionRequirements.deserialize(test_json)).serialize()

    def test_is_holder(self):
        test_json = """
            {
                "field_id": [
                    "ce66380c-1990-4aec-b8b4-5d532e92a616",
                    "dd69e8a4-4cc0-4540-b34a-b4aa0e0d2214",
                    "d15802b4-eec8-45ef-b78f-e35125ac1bb8",
                    "765f3e09-600c-467f-99eb-ea549c350121"
                ],
                "directive": "required"
            }
        """
        expected_result = json.loads(test_json)
        actual_result = (Holder.deserialize(test_json)).serialize()
        assert expected_result == actual_result

    def test_filter(self):
        test_json_list = []
        test_json_string_enum = """
            {
              "type":"string",
              "enum": ["testa1", "testa2", "testa3"]
            }
        """
        test_json_list.append(test_json_string_enum)
        test_json_number_enum = """
            {
              "type":"string",
              "enum": ["testb1", "testb2", "testb3"]
            }
        """
        test_json_list.append(test_json_number_enum)
        test_json_not_enum = """
            {
                "not": {
                    "enum": ["testc1", "testc2", "testc3"]
                }
            }
        """
        test_json_list.append(test_json_not_enum)
        test_json_format_min = """
            {
                "type":"string",
                "format": "date",
                "minimum": "1980/07/04" 
            }
        """
        test_json_list.append(test_json_format_min)
        test_json_exclmax = """
            {
                "type":"number",
                "exclusiveMaximum": 2
            }
        """
        test_json_list.append(test_json_exclmax)
        test_json_exclmin = """
            {
                "exclusiveMinimum": 2
            }
        """
        test_json_list.append(test_json_exclmin)
        test_json_const = """
            {
                "const": 2.0
            }
        """
        test_json_list.append(test_json_const)
        test_json_enum_error = """
            {
                "enum": 2
            }
        """
        test_json_custom_field_error = """
            {
                "minimum": [
                    "not_valid"
                ]
            }
        """

        for tmp_test_item in test_json_list:
            expected_result = json.loads(tmp_test_item)
            actual_result = (Filter.deserialize(tmp_test_item)).serialize()
            assert expected_result == actual_result

        with self.assertRaises(BaseModelError) as cm:
            (Filter.deserialize(test_json_enum_error)).serialize()

        with self.assertRaises(BaseModelError) as cm:
            (Filter.deserialize(test_json_custom_field_error)).serialize()

    def test_constraints(self):
        test_json = """
            {
                "fields":[
                    {
                        "path":[
                            "$.credentialSubject.dob",
                            "$.vc.credentialSubject.dob",
                            "$.credentialSubject.license.dob"
                        ],
                        "filter":{
                        "type":"string",
                        "format":"date",
                        "minimum":"1999-5-16"
                        }
                    }
                ],
                "statuses": {
                    "active": {
                        "directive": "required"
                    },
                    "suspended": {
                        "directive": "allowed"
                    },
                    "revoked": {
                        "directive": "disallowed"
                    }
                }
            }
        """

        expected_result = json.loads(test_json)
        actual_result = (Constraints.deserialize(test_json)).serialize()
        assert expected_result == actual_result
