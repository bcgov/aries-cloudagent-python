import json

from os.path import join

from asynctest import TestCase as AsyncTestCase, mock as async_mock

from ....core.in_memory import InMemoryProfile
from ....indy.issuer import IndyIssuer, IndyIssuerError
from ....indy.sdk.models.revocation import IndyRevRegDef
from ....indy.util import indy_client_dir
from ....ledger.base import BaseLedger
from ....tails.base import BaseTailsServer
from ....wallet.did_info import DIDInfo

from ...error import RevocationError

from .. import issuer_rev_reg_record as test_module
from ..issuer_rev_reg_record import IssuerRevRegRecord
from ..revocation_registry import RevocationRegistry

TEST_DID = "55GkHamhTU1ZbTbV2ab9DE"
CRED_DEF_ID = f"{TEST_DID}:3:CL:1234:default"
REV_REG_ID = f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:0"
TAILS_HASH = "3MLjUFQz9x9n5u9rFu8Ba9C5bo4HNFjkPNc54jZPSNaZ"
TAILS_URI = "http://tails.ca/3MLj"

REV_REG_DEF = {
    "ver": "1.0",
    "id": REV_REG_ID,
    "revocDefType": "CL_ACCUM",
    "tag": "default",
    "credDefId": CRED_DEF_ID,
    "value": {
        "issuanceType": "ISSUANCE_ON_DEMAND",
        "maxCredNum": 5,
        "publicKeys": {
            "accumKey": {
                "z": "1 120F522F81E6B71556D4CAE43ED6DB3EEE154ABBD4443108E0F41A989682B6E9 1 20FA951E9B7714EAB189BD9AA2BE6F165D86327C01BEB39B2F13737EC8FEC7AC 1 209F1257F3A54ABE76140DDF6740E54BB132A682521359A32AF7B194E55E22E1 1 09F7A59005C49398548E2CF68F03E95F2724BB12432E51A351FC22208EC9B96B 1 1FAD806F8BAA3BD98B32DD9237399C35AB207E7D39C3F240789A3196394B3357 1 0C0DB1C207DAC540DA70556486BEC1671C0B8649CA0685810AFC2C0A2A29A2F1 1 08DF0DF68F7B662130DE9E756695E6DAD8EE7E7FE0CE140FB6E4C8669C51C431 1 1FB49B2822014FC18BDDC7E1FE42561897BEF809B1ED5FDCF4AD3B46975469A0 1 1EDA5FF53A25269912A7646FBE7E9110C443D695C96E70DC41441DB62CA35ADF 1 217FEA48FB4FBFC850A62C621C00F2CCF1E2DBBA118302A2B976E337B74F3F8F 1 0DD4DD3F9350D4026AF31B33213C9CCE27F1771C082676CCC0DB870C46343BC1 1 04C490B80545D203B743579054F8198D7515190649679D0AB8830DFFC3640D0A"
            }
        },
        "tailsHash": TAILS_HASH,
        "tailsLocation": TAILS_URI,
    },
}
REV_REG_ENTRY = {
    "ver": "1.0",
    "value": {
        "accum": "21 11792B036AED0AAA12A46CF39347EB35C865DAC99F767B286F6E37FF0FF4F1CBE 21 12571556D2A1B4475E81295FC8A4F0B66D00FB78EE8C7E15C29C2CA862D0217D4 6 92166D2C2A3BC621AD615136B7229AF051AB026704BF8874F9F0B0106122BF4F 4 2C47BCBBC32904161E2A2926F120AD8F40D94C09D1D97DA735191D27370A68F8 6 8CC19FDA63AB16BEA45050D72478115BC1CCB8E47A854339D2DD5E112976FFF7 4 298B2571FFC63A737B79C131AC7048A1BD474BF907AF13BC42E533C79FB502C7"
    },
}


class TestIssuerRevRegRecord(AsyncTestCase):
    async def setUp(self):
        self.profile = InMemoryProfile.test_profile(
            settings={"tails_server_base_url": "http://1.2.3.4:8088"},
        )

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
        rec0 = IssuerRevRegRecord()
        await rec0.save(self.session, reason="a record")
        rec1 = IssuerRevRegRecord()
        await rec1.save(self.session, reason="another record")
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
            json.dumps(REV_REG_DEF),
            json.dumps(REV_REG_ENTRY),
        )

        with async_mock.patch.object(
            test_module, "move", async_mock.MagicMock()
        ) as mock_move:
            await rec.generate_registry(self.profile)

        assert rec.revoc_reg_id == REV_REG_ID
        assert rec.state == IssuerRevRegRecord.STATE_GENERATED
        assert rec.tails_hash == TAILS_HASH
        assert rec.tails_local_path == join(
            indy_client_dir(join("tails", REV_REG_ID)), rec.tails_hash
        )
        with self.assertRaises(RevocationError):
            await rec.set_tails_file_public_uri(self.profile, "dummy")

        await rec.set_tails_file_public_uri(self.profile, TAILS_URI)
        assert rec.tails_public_uri == TAILS_URI
        assert rec.revoc_reg_def["value"]["tailsLocation"] == TAILS_URI

        await rec.send_def(self.profile)
        assert rec.state == IssuerRevRegRecord.STATE_POSTED
        self.ledger.send_revoc_reg_def.assert_called_once()

        await rec.send_entry(self.profile)
        assert rec.state == IssuerRevRegRecord.STATE_ACTIVE
        self.ledger.send_revoc_reg_entry.assert_called_once()

        rev_reg = await rec.get_registry()
        assert type(rev_reg) == RevocationRegistry

        queried = await IssuerRevRegRecord.query_by_cred_def_id(
            session=self.session,
            cred_def_id=CRED_DEF_ID,
            state=IssuerRevRegRecord.STATE_ACTIVE,
        )
        assert len(queried) == 1

        retrieved = await IssuerRevRegRecord.retrieve_by_revoc_reg_id(
            session=self.session, revoc_reg_id=rec.revoc_reg_id
        )
        assert retrieved.revoc_reg_id == rec.revoc_reg_id

        await rec.set_state(self.session)
        assert rec.state == IssuerRevRegRecord.STATE_FULL

        data = rec.serialize()
        model_instance = IssuerRevRegRecord.deserialize(data)
        assert isinstance(model_instance, IssuerRevRegRecord)
        assert model_instance == rec

    async def test_operate_on_full_record(self):
        rec_full = IssuerRevRegRecord(
            issuer_did=TEST_DID,
            revoc_reg_id=REV_REG_ID,
            revoc_reg_def=REV_REG_DEF,
            revoc_def_type="CL_ACCUM",
            revoc_reg_entry=REV_REG_ENTRY,
            cred_def_id=CRED_DEF_ID,
            state=IssuerRevRegRecord.STATE_FULL,
            tails_public_uri=TAILS_URI,
        )

        with self.assertRaises(RevocationError) as x_state:
            await rec_full.generate_registry(self.profile)

        with self.assertRaises(RevocationError) as x_state:
            await rec_full.send_def(self.profile)

        rec_full.state = IssuerRevRegRecord.STATE_INIT
        with self.assertRaises(RevocationError) as x_state:
            await rec_full.send_entry(self.profile)

    async def test_pending(self):
        rec = IssuerRevRegRecord()
        await rec.mark_pending(self.session, "1")
        await rec.mark_pending(self.session, "2")
        await rec.mark_pending(self.session, "3")
        await rec.mark_pending(self.session, "4")

        found = await IssuerRevRegRecord.query_by_pending(self.session)
        assert len(found) == 1 and found[0] == rec

        await rec.clear_pending(self.session, ["1", "2"])
        assert rec.pending_pub == ["3", "4"]
        found = await IssuerRevRegRecord.query_by_pending(self.session)
        assert found

        await rec.clear_pending(self.session, [])
        assert rec.pending_pub == []
        found = await IssuerRevRegRecord.query_by_pending(self.session)
        assert not found

        await rec.mark_pending(self.session, "5")
        await rec.mark_pending(self.session, "6")

        await rec.clear_pending(self.session, [])
        assert rec.pending_pub == []
        found = await IssuerRevRegRecord.query_by_pending(self.session)
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
                json.dumps(REV_REG_DEF),
                json.dumps(REV_REG_ENTRY),
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

    async def test_serde(self):
        rr_def = IndyRevRegDef.deserialize(REV_REG_DEF)
        for arg in [rr_def, rr_def.serialize()]:
            irr_rec = IssuerRevRegRecord(
                issuer_did=TEST_DID,
                revoc_reg_id=REV_REG_ID,
                revoc_reg_def=arg,
                revoc_def_type="CL_ACCUM",
                revoc_reg_entry=REV_REG_ENTRY,
                cred_def_id=CRED_DEF_ID,
                state=IssuerRevRegRecord.STATE_FULL,
                tails_public_uri=TAILS_URI,
            )

            assert type(irr_rec.revoc_reg_def) == dict
            assert type(irr_rec.revoc_reg_entry) == dict
            ser = irr_rec.serialize()
            deser = IssuerRevRegRecord.deserialize(ser)
            assert type(deser.revoc_reg_def) == dict
            assert type(deser.revoc_reg_entry) == dict
