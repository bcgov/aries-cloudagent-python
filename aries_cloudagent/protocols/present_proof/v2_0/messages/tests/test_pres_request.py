import json
import pytest

from datetime import datetime, timezone
from unittest import TestCase

from ......indy.sdk.models.pres_preview import PRESENTATION_PREVIEW
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......messaging.models.base import BaseModelError
from ......messaging.util import str_to_datetime, str_to_epoch

from .....didcomm_prefix import DIDCommPrefix

from ...message_types import ATTACHMENT_FORMAT, PRES_20_REQUEST

from ..pres_format import V20PresFormat
from ..pres_request import V20PresRequest, V20PresRequestSchema

CD_ID = f"NcYxiDXkpYi6ov5FcYDi1e:3:CL:12:tag1"
INDY_PROOF_REQ = [
    {
        "name": "proof-req",
        "version": "1.0",
        "nonce": "12345",
        "requested_attributes": {
            "0_player_uuid": {
                "name": "player",
                "restrictions": [
                    {
                        "cred_def_id": f"{CD_ID}",
                        "attr::player::value": "Richie Knucklez",
                    }
                ],
                "non_revoked": {
                    "from": 1234567890,
                    "to": 1234567890,
                },
            },
            "0_screencapture_uuid": {
                "name": "screenCapture",
                "restrictions": [{"cred_def_id": f"{CD_ID}"}],
                "non_revoked": {
                    "from": 1234567890,
                    "to": 1234567890,
                },
            },
        },
        "requested_predicates": {
            "0_highscore_GE_uuid": {
                "name": "highScore",
                "p_type": ">=",
                "p_value": 1000000,
                "restrictions": [{"cred_def_id": f"{CD_ID}"}],
                "non_revoked": {
                    "from": 1234567890,
                    "to": 1234567890,
                },
            }
        },
    },
    {
        "name": "proof-req",
        "version": "1.0",
        "nonce": "123456",
        "requested_attributes": {
            "0_player_uuid": {
                "name": "player",
                "restrictions": [{"cred_def_id": f"{CD_ID}"}],
            },
            "0_screencapture_uuid": {
                "name": "screenCapture",
                "restrictions": [{"cred_def_id": f"{CD_ID}"}],
            },
        },
        "requested_predicates": {
            "0_highscore_GE_uuid": {
                "name": "highScore",
                "p_type": ">=",
                "p_value": 1000000,
                "restrictions": [{"cred_def_id": f"{CD_ID}"}],
            }
        },
    },
    {
        "name": "proof-req",
        "version": "1.0",
        "nonce": "1234567",
        "requested_attributes": {},
        "requested_predicates": {
            "0_highscore_GE_uuid": {
                "name": "highScore",
                "p_type": ">=",
                "p_value": 1000000,
                "restrictions": [{"cred_def_id": f"{CD_ID}"}],
            }
        },
    },
]

PRES_REQ = [
    V20PresRequest(
        comment="Test",
        will_confirm=True,
        formats=[
            V20PresFormat(
                attach_id="indy",
                format_=ATTACHMENT_FORMAT[PRES_20_REQUEST][
                    V20PresFormat.Format.INDY.api
                ],
            )
        ],
        request_presentations_attach=[
            AttachDecorator.data_base64(mapping=proof_req, ident="indy")
        ],
    )
    for proof_req in INDY_PROOF_REQ
]


class TestV20PresRequest(TestCase):
    """Presentation request tests."""

    def test_init_type(self):
        """Test initializer and type."""
        for i, pres_req in enumerate(PRES_REQ):
            assert pres_req.will_confirm
            assert len(pres_req.formats) == len(pres_req.request_presentations_attach)
            assert pres_req.request_presentations_attach[0].content == INDY_PROOF_REQ[i]
            assert pres_req.attachment(V20PresFormat.Format.INDY) == INDY_PROOF_REQ[i]
            assert pres_req._type == DIDCommPrefix.qualify_current(PRES_20_REQUEST)

    def test_attachment_no_target_format(self):
        """Test attachment behaviour for only unknown formats."""

        x_pres_req = V20PresRequest(
            comment="Test",
            formats=[V20PresFormat(attach_id="not_indy", format_="not_indy")],
            request_presentations_attach=[
                AttachDecorator.data_base64(
                    ident="not_indy", mapping=PRES_REQ[0].serialize()
                )
            ],
        )
        assert x_pres_req.attachment() is None

    def test_serde(self):
        """Test de/serialization."""
        for pres_req_msg in PRES_REQ:
            pres_req_dict = pres_req_msg.serialize()
            pres_req_obj = V20PresRequest.deserialize(pres_req_dict)
            assert type(pres_req_obj) == V20PresRequest

            pres_req_dict["request_presentations~attach"][0]["data"][
                "base64"
            ] = "eyJub3QiOiAiaW5keSJ9"
            with self.assertRaises(BaseModelError):
                V20PresRequest.deserialize(pres_req_dict)

            pres_req_dict["request_presentations~attach"][0]["@id"] = "xxx"
            with self.assertRaises(BaseModelError):
                V20PresRequest.deserialize(pres_req_dict)

            pres_req_dict["request_presentations~attach"].append(
                {
                    "@id": "def",
                    "mime-type": "application/json",
                    "data": {"base64": "eyJub3QiOiAiaW5keSJ9"},
                }
            )  # more attachments than formats
            with self.assertRaises(BaseModelError):
                V20PresRequest.deserialize(pres_req_dict)

            pres_req_msg.formats.append(  # unknown format: no validation
                V20PresFormat(
                    attach_id="not_indy",
                    format_="not_indy",
                )
            )
            obj = pres_req_msg.serialize()
            obj["request_presentations~attach"].append(
                {
                    "@id": "not_indy",
                    "mime-type": "application/json",
                    "data": {"base64": "eyJub3QiOiAiaW5keSJ9"},
                }
            )
            V20PresRequest.deserialize(obj)
