import json

from os.path import join

from asynctest import TestCase as AsyncTestCase, mock as async_mock

from ....core.in_memory import InMemoryProfile
from ....indy.issuer import IndyIssuer, IndyIssuerError
from ....indy.util import indy_client_dir
from ....ledger.base import BaseLedger
from ....tails.base import BaseTailsServer

from ...error import RevocationError

from .. import issuer_rev_reg_record as test_module
from ..issuer_rev_reg_record import IssuerRevRegRecord
from ..revocation_registry import RevocationRegistry

TEST_DID = "55GkHamhTU1ZbTbV2ab9DE"
CRED_DEF_ID = f"{TEST_DID}:3:CL:1234:default"
REV_REG_ID = f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:0"


class TestIssuerRevRegRecord(AsyncTestCase):
    async def setUp(self):
        self.profile = InMemoryProfile.test_profile(
            settings={"tails_server_base_url": "http://1.2.3.4:8088"},
        )
        self.context = self.profile.context

        Ledger = async_mock.MagicMock(BaseLedger, autospec=True)
        self.ledger = Ledger()
        self.ledger.send_revoc_reg_def = async_mock.CoroutineMock()
        self.ledger.send_revoc_reg_entry = async_mock.CoroutineMock()
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        TailsServer = async_mock.MagicMock(BaseTailsServer, autospec=True)
        self.tails_server = TailsServer()
        self.tails_server.upload_tails_file = async_mock.CoroutineMock(
            return_value=(False, "Internal Server Error")
        )
        self.profile.context.injector.bind_instance(BaseTailsServer, self.tails_server)

        self.session = await self.profile.session()

    async def test_order(self):
        async with self.profile.session() as session:
            rec0 = IssuerRevRegRecord()
            await rec0.save(session, reason="a record")
            rec1 = IssuerRevRegRecord()
            await rec1.save(session, reason="another record")
            assert rec0 < rec1

    async def test_generate_registry_etc(self):
        rec = IssuerRevRegRecord(
            issuer_did=TEST_DID,
            cred_def_id=CRED_DEF_ID,
            revoc_reg_id=REV_REG_ID,
        )
        issuer = async_mock.MagicMock(IndyIssuer)
        self.profile.context.injector.bind_instance(IndyIssuer, issuer)

        with async_mock.patch.object(
            issuer, "create_and_store_revocation_registry", async_mock.CoroutineMock()
        ) as mock_create_store_rr:
            mock_create_store_rr.side_effect = IndyIssuerError("Not this time")

            with self.assertRaises(RevocationError):
                await rec.generate_registry(self.profile)

        issuer.create_and_store_revocation_registry.return_value = (
            REV_REG_ID,
            json.dumps(
                {
                    "value": {
                        "tailsHash": "59NY25UEV8a5CzNkXFQMppwofUxtYtf4FDp1h9xgeLcK",
                        "tailsLocation": "point at infinity",
                    }
                }
            ),
            json.dumps({"revoc_reg_entry": "dummy-entry"}),
        )

        with async_mock.patch.object(
            test_module, "move", async_mock.MagicMock()
        ) as mock_move:
            await rec.generate_registry(self.profile)

        assert rec.revoc_reg_id == REV_REG_ID
        assert rec.state == IssuerRevRegRecord.STATE_GENERATED
        assert rec.tails_hash == "59NY25UEV8a5CzNkXFQMppwofUxtYtf4FDp1h9xgeLcK"
        assert rec.tails_local_path == join(
            indy_client_dir(join("tails", REV_REG_ID)), rec.tails_hash
        )
        with self.assertRaises(RevocationError):
            await rec.set_tails_file_public_uri(self.profile, "dummy")

        await rec.set_tails_file_public_uri(self.profile, "http://localhost/dummy")
        assert rec.tails_public_uri == "http://localhost/dummy"
        assert rec.revoc_reg_def["value"]["tailsLocation"] == "http://localhost/dummy"

        await rec.send_def(self.profile)
        assert rec.state == IssuerRevRegRecord.STATE_POSTED
        self.ledger.send_revoc_reg_def.assert_called_once()

        await rec.send_entry(self.profile)
        assert rec.state == IssuerRevRegRecord.STATE_ACTIVE
        self.ledger.send_revoc_reg_entry.assert_called_once()

        rev_reg = await rec.get_registry()
        assert type(rev_reg) == RevocationRegistry

        async with self.profile.session() as session:
            queried = await IssuerRevRegRecord.query_by_cred_def_id(
                session=session,
                cred_def_id=CRED_DEF_ID,
                state=IssuerRevRegRecord.STATE_ACTIVE,
            )
            assert len(queried) == 1

            retrieved = await IssuerRevRegRecord.retrieve_by_revoc_reg_id(
                session=session, revoc_reg_id=rec.revoc_reg_id
            )
            assert retrieved.revoc_reg_id == rec.revoc_reg_id

            await rec.set_state(session)
            assert rec.state == IssuerRevRegRecord.STATE_FULL

        data = rec.serialize()
        model_instance = IssuerRevRegRecord.deserialize(data)
        assert isinstance(model_instance, IssuerRevRegRecord)
        assert model_instance == rec

    async def test_operate_on_full_record(self):
        rec_full = IssuerRevRegRecord(
            issuer_did=TEST_DID,
            revoc_reg_id=REV_REG_ID,
            revoc_reg_def={"sample": "rr-def"},
            revoc_def_type="CL_ACCUM",
            revoc_reg_entry={"sample": "rr-ent"},
            cred_def_id=CRED_DEF_ID,
            state=IssuerRevRegRecord.STATE_FULL,
            tails_public_uri="http://localhost/dummy/path",
        )

        with self.assertRaises(RevocationError) as x_state:
            await rec_full.generate_registry(self.profile)

        with self.assertRaises(RevocationError) as x_state:
            await rec_full.send_def(self.profile)

        rec_full.state = IssuerRevRegRecord.STATE_INIT
        with self.assertRaises(RevocationError) as x_state:
            await rec_full.send_entry(self.profile)

    async def test_pending(self):
        async with self.profile.session() as session:
            rec = IssuerRevRegRecord()
            await rec.mark_pending(session, "1")
            await rec.mark_pending(session, "2")
            await rec.mark_pending(session, "3")
            await rec.mark_pending(session, "4")

            found = await IssuerRevRegRecord.query_by_pending(session)
            assert len(found) == 1 and found[0] == rec

            await rec.clear_pending(session, ["1", "2"])
            assert rec.pending_pub == ["3", "4"]
            found = await IssuerRevRegRecord.query_by_pending(session)
            assert found

            await rec.clear_pending(session, [])
            assert rec.pending_pub == []
            found = await IssuerRevRegRecord.query_by_pending(session)
            assert not found

            await rec.mark_pending(session, "5")
            await rec.mark_pending(session, "6")

            await rec.clear_pending(session, [])
            assert rec.pending_pub == []
            found = await IssuerRevRegRecord.query_by_pending(session)
            assert not found

    async def test_set_tails_file_public_uri_rev_reg_undef(self):
        rec = IssuerRevRegRecord()
        with self.assertRaises(RevocationError):
            await rec.set_tails_file_public_uri(self.profile, "dummy")

    async def test_stage_pending_registry(self):
        issuer = async_mock.MagicMock(IndyIssuer)
        issuer.create_and_store_revocation_registry = async_mock.CoroutineMock(
            return_value=(
                REV_REG_ID,
                json.dumps(
                    {
                        "value": {
                            "tailsHash": "abcd1234",
                            "tailsLocation": "/tmp/location",
                        }
                    }
                ),
                json.dumps({"revoc_reg_entry": "dummy-entry"}),
            )
        )
        self.profile.context.injector.bind_instance(IndyIssuer, issuer)
        rec = IssuerRevRegRecord(
            issuer_did=TEST_DID,
            revoc_reg_id=REV_REG_ID,
        )

        with async_mock.patch.object(
            test_module, "move", async_mock.MagicMock()
        ) as mock_move:
            await rec.stage_pending_registry(self.profile)

    async def test_send_rev_reg_undef(self):
        rec = IssuerRevRegRecord()
        with self.assertRaises(RevocationError):
            await rec.send_def(self.profile)

        with self.assertRaises(RevocationError):
            await rec.send_entry(self.profile)
