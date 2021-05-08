import pytest

from unittest import TestCase

from ......indy.sdk.models.pres_preview import (
    IndyPresAttrSpec,
    IndyPresPredSpec,
    IndyPresPreview,
    PRESENTATION_PREVIEW,
)
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......messaging.models.base import BaseModelError

from .....didcomm_prefix import DIDCommPrefix

from ...message_types import ATTACHMENT_FORMAT, PRES_20_PROPOSAL

from ..pres_format import V20PresFormat
from ..pres_proposal import V20PresProposal

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


class TestV20PresProposal(TestCase):
    """Presentation proposal tests."""

    def test_init_type_attachment_serde(self):
        """Test initializer, type, attachment, de/serialization."""
        for proof_req in INDY_PROOF_REQ:
            pres_proposal = V20PresProposal(
                comment="Hello World",
                formats=[
                    V20PresFormat(
                        attach_id="indy",
                        format_=ATTACHMENT_FORMAT[PRES_20_PROPOSAL][
                            V20PresFormat.Format.INDY.api
                        ],
                    )
                ],
                proposals_attach=[AttachDecorator.data_base64(proof_req, ident="indy")],
            )
            assert pres_proposal._type == DIDCommPrefix.qualify_current(
                PRES_20_PROPOSAL
            )
            assert pres_proposal.attachment(V20PresFormat.Format.INDY) == proof_req

            pres_proposal_ser = pres_proposal.serialize()
            pres_proposal_deser = V20PresProposal.deserialize(pres_proposal_ser)
            assert type(pres_proposal_deser) == V20PresProposal

            pres_proposal_dict = pres_proposal_deser.serialize()
            assert pres_proposal_dict == pres_proposal_ser

            pres_proposal_dict["formats"][0]["attach_id"] = "xxx"
            with pytest.raises(BaseModelError):
                V20PresProposal.deserialize(pres_proposal_dict)  # id mismatch

            pres_proposal_dict["formats"] = []
            with pytest.raises(BaseModelError):
                V20PresProposal.deserialize(pres_proposal_dict)  # length mismatch

            pres_proposal.formats.append(  # unknown format: no validation
                V20PresFormat(
                    attach_id="not_indy",
                    format_="not_indy",
                )
            )
            obj = pres_proposal.serialize()
            obj["proposals~attach"].append(
                {
                    "@id": "not_indy",
                    "mime-type": "application/json",
                    "data": {"base64": "eyJub3QiOiAiaW5keSJ9"},
                }
            )
            V20PresProposal.deserialize(obj)

    def test_attachment_no_target_format(self):
        """Test attachment behaviour for only unknown formats."""

        x_pres_proposal = V20PresProposal(
            comment="Test",
            formats=[V20PresFormat(attach_id="not_indy", format_="not_indy")],
            proposals_attach=[
                AttachDecorator.data_base64(ident="not_indy", mapping=INDY_PROOF_REQ[0])
            ],
        )
        assert x_pres_proposal.attachment() is None
