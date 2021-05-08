import json

from asynctest import TestCase as AsyncTestCase, mock as async_mock

from .....didcomm_prefix import DIDCommPrefix

from .....didexchange.v1_0.message_types import ARIES_PROTOCOL as DIDX_PROTO

from ...messages.invitation import InvitationMessage

from ..invitation import InvitationRecord, InvitationRecordSchema

TEST_DID = "55GkHamhTU1ZbTbV2ab9DE"


class TestInvitationRecord(AsyncTestCase):
    def test_invitation_record(self):
        """Test invitation record."""
        invi_rec = InvitationRecord(invi_msg_id="12345")
        assert invi_rec.invitation_id is None  # not saved
        assert isinstance(invi_rec, InvitationRecord)
        assert invi_rec.record_value == {
            "invitation": None,
            "invitation_url": None,
            "state": None,
            "trace": False,
        }

        another = InvitationRecord(invi_msg_id="99999")
        assert invi_rec != another


class TestInvitationRecordSchema(AsyncTestCase):
    def test_make_record(self):
        """Test making record."""
        invi = InvitationMessage(
            comment="Hello",
            label="A label",
            handshake_protocols=[DIDCommPrefix.qualify_current(DIDX_PROTO)],
            services=[TEST_DID],
        )
        data = {
            "invitation_id": "0",
            "state": InvitationRecord.STATE_AWAIT_RESPONSE,
            "invitation": invi.serialize(),
        }
        model_instance = InvitationRecord.deserialize(data)
        assert isinstance(model_instance, InvitationRecord)

        assert data.items() <= model_instance.serialize().items()

        model_instance = InvitationRecord(
            invitation_id="0",
            state=InvitationRecord.STATE_AWAIT_RESPONSE,
            invitation=invi,
        )
        assert data.items() <= model_instance.serialize().items()
        model_instance = InvitationRecord(
            invitation_id="0",
            state=InvitationRecord.STATE_AWAIT_RESPONSE,
            invitation=invi.serialize(),
        )
        assert data.items() <= model_instance.serialize().items()
