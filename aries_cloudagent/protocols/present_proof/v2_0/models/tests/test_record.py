from unittest import TestCase as UnitTestCase

from ......indy.sdk.models.pres_preview import (
    IndyPresAttrSpec,
    IndyPresPredSpec,
    IndyPresPreview,
)
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema

from ...message_types import ATTACHMENT_FORMAT, PRES_20_PROPOSAL
from ...messages.pres_format import V20PresFormat
from ...messages.pres_proposal import V20PresProposal

from ..pres_exchange import V20PresExRecord

S_ID = "NcYxiDXkpYi6ov5FcYDi1e:2:vidya:1.0"
CD_ID = f"NcYxiDXkpYi6ov5FcYDi1e:3:CL:{S_ID}:tag1"
INDY_PROOF_REQ = {
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
}


class BasexRecordImpl(BaseExchangeRecord):
    class Meta:
        schema_class = "BasexRecordImplSchema"

    RECORD_TYPE = "record"


class BasexRecordImplSchema(BaseExchangeSchema):
    class Meta:
        model_class = BasexRecordImpl


class TestRecord(UnitTestCase):
    def test_record(self):
        record = V20PresExRecord(
            pres_ex_id="pxid",
            thread_id="thid",
            connection_id="conn_id",
            initiator="init",
            role="role",
            state="state",
            pres_proposal={"pres": "prop"},
            pres_request={"pres": "req"},
            pres={"pres": "pres"},
            verified="false",
            auto_present=True,
            error_msg="error",
        )

        assert record.pres_ex_id == "pxid"

        assert record.record_value == {
            "connection_id": "conn_id",
            "initiator": "init",
            "role": "role",
            "state": "state",
            "pres_proposal": {"pres": "prop"},
            "pres_request": {"pres": "req"},
            "pres": {"pres": "pres"},
            "verified": "false",
            "auto_present": True,
            "error_msg": "error",
            "trace": False,
        }

        bx_record = BasexRecordImpl()
        assert record != bx_record

    def test_serde(self):
        """Test de/serialization."""

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
            proposals_attach=[
                AttachDecorator.data_base64(INDY_PROOF_REQ, ident="indy")
            ],
        )
        for proposal_arg in [pres_proposal, pres_proposal.serialize()]:
            px_rec = V20PresExRecord(
                pres_ex_id="dummy",
                connection_id="0000...",
                thread_id="dummy-thid",
                initiator=V20PresExRecord.INITIATOR_SELF,
                role=V20PresExRecord.ROLE_PROVER,
                state=V20PresExRecord.STATE_PROPOSAL_SENT,
                pres_proposal=proposal_arg,
                pres_request=None,
                pres=None,
                verified=None,
                auto_present=True,
                error_msg=None,
                trace=False,
            )

            assert type(px_rec.pres_proposal) == dict
            ser = px_rec.serialize()
            deser = V20PresExRecord.deserialize(ser)
            assert type(deser.pres_proposal) == dict
