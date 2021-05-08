from unittest import TestCase as UnitTestCase

from ......indy.sdk.models.pres_preview import (
    IndyPresAttrSpec,
    IndyPresPredSpec,
    IndyPresPreview,
)
from ......messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema

from ...messages.presentation_proposal import PresentationProposal

from ..presentation_exchange import V10PresentationExchange

S_ID = "NcYxiDXkpYi6ov5FcYDi1e:2:vidya:1.0"
CD_ID = f"NcYxiDXkpYi6ov5FcYDi1e:3:CL:{S_ID}:tag1"
PRES_PREVIEW = IndyPresPreview(
    attributes=[
        IndyPresAttrSpec(name="player", cred_def_id=CD_ID, value="Richie Knucklez"),
        IndyPresAttrSpec(
            name="screenCapture",
            cred_def_id=CD_ID,
            mime_type="image/png",
            value="aW1hZ2luZSBhIHNjcmVlbiBjYXB0dXJl",
        ),
    ],
    predicates=[
        IndyPresPredSpec(
            name="highScore", cred_def_id=CD_ID, predicate=">=", threshold=1000000
        )
    ],
)


class BasexRecordImpl(BaseExchangeRecord):
    class Meta:
        schema_class = "BasexRecordImplSchema"

    RECORD_TYPE = "record"


class BasexRecordImplSchema(BaseExchangeSchema):
    class Meta:
        model_class = BasexRecordImpl


class TestRecord(UnitTestCase):
    def test_record(self):
        record = V10PresentationExchange(
            presentation_exchange_id="pxid",
            connection_id="connid",
            thread_id="thid",
            initiator="init",
            role="role",
            state="state",
            presentation_proposal_dict={"prop": "dict"},
            presentation_request={"pres": "req"},
            presentation_request_dict={"pres", "dict"},
            presentation={"pres": "indy"},
            verified="false",
            auto_present=True,
            error_msg="error",
        )

        assert record.presentation_exchange_id == "pxid"

        assert record.record_value == {
            "connection_id": "connid",
            "initiator": "init",
            "presentation_proposal_dict": {"prop": "dict"},
            "presentation_request": {"pres": "req"},
            "presentation_request_dict": {"pres", "dict"},
            "presentation": {"pres": "indy"},
            "role": "role",
            "state": "state",
            "auto_present": True,
            "error_msg": "error",
            "verified": "false",
            "trace": False,
        }

        bx_record = BasexRecordImpl()
        assert record != bx_record

    def test_serde(self):
        """Test de/serialization."""

        presentation_proposal = PresentationProposal(
            comment="Hello World", presentation_proposal=PRES_PREVIEW
        )
        for proposal_arg in [presentation_proposal, presentation_proposal.serialize()]:
            px_rec = V10PresentationExchange(
                presentation_exchange_id="dummy",
                connection_id="0000...",
                thread_id="dummy-thid",
                initiator=V10PresentationExchange.INITIATOR_SELF,
                role=V10PresentationExchange.ROLE_PROVER,
                state=V10PresentationExchange.STATE_PROPOSAL_SENT,
                presentation_proposal_dict=proposal_arg,
                presentation_request=None,
                presentation_request_dict=None,
                presentation=None,
                verified=None,
                auto_present=True,
                error_msg=None,
                trace=False,
            )

            assert type(px_rec.presentation_proposal_dict) == dict
            ser = px_rec.serialize()
            deser = V10PresentationExchange.deserialize(ser)
            assert type(deser.presentation_proposal_dict) == dict
