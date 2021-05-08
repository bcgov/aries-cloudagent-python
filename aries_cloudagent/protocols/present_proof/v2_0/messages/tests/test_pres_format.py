from unittest import TestCase

from marshmallow import ValidationError

from ......indy.sdk.models.pres_preview import (
    IndyPresAttrSpec,
    IndyPresPreview,
    IndyPresPredSpec,
)
from ......messaging.decorators.attach_decorator import AttachDecorator

from ..pres_format import V20PresFormat

CD_ID = "GMm4vMw8LLrLJjp81kRRLp:3:CL:12:tag"
INDY_PROOF_REQ = [
    {
        "name": "proof-req",
        "version": "1.0",
        "nonce": "12345",
        "requested_attributes": {
            "0_player_uuid": {
                "name": "player",
                "restrictions": [{"cred_def_id": f"{CD_ID}"}],
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


class TestV20FormatFormat(TestCase):
    """Coverage for self-get."""

    def test_get_completeness(self):
        assert (
            V20PresFormat.Format.get(V20PresFormat.Format.INDY)
            is V20PresFormat.Format.INDY
        )
        assert V20PresFormat.Format.get("no such format") is None
        assert V20PresFormat.Format.get("hlindy/...") is V20PresFormat.Format.INDY
        assert (
            V20PresFormat.Format.get(V20PresFormat.Format.DIF.api)
            is V20PresFormat.Format.DIF
        )

    def test_get_attachment_data(self):
        for proof_req in INDY_PROOF_REQ:
            assert (
                V20PresFormat.Format.INDY.get_attachment_data(
                    formats=[
                        V20PresFormat(
                            attach_id="indy",
                            format_=V20PresFormat.Format.INDY,
                        )
                    ],
                    attachments=[
                        AttachDecorator.data_base64(mapping=proof_req, ident="indy")
                    ],
                )
                == proof_req
            )

            assert (
                V20PresFormat.Format.INDY.get_attachment_data(
                    formats=[
                        V20PresFormat(
                            attach_id="indy",
                            format_=V20PresFormat.Format.INDY,
                        )
                    ],
                    attachments=[AttachDecorator.data_base64(proof_req, ident="xxx")],
                )
                is None
            )

            assert (
                V20PresFormat.Format.DIF.get_attachment_data(
                    formats=[
                        V20PresFormat(
                            attach_id="indy",
                            format_=V20PresFormat.Format.INDY,
                        )
                    ],
                    attachments=[AttachDecorator.data_base64(proof_req, ident="indy")],
                )
                is None
            )
