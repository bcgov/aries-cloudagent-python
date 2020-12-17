import pytest

from asynctest import mock as async_mock, TestCase as AsyncTestCase

from ...core.in_memory import InMemoryProfile
from ...ledger.base import BaseLedger
from ...storage.error import StorageNotFoundError

from ..error import (
    RevocationNotSupportedError,
    RevocationRegistryBadSizeError,
)
from ..indy import IndyRevocation
from ..models.issuer_rev_reg_record import DEFAULT_REGISTRY_SIZE, IssuerRevRegRecord
from ..models.revocation_registry import RevocationRegistry


@pytest.mark.indy
class TestIndyRevocation(AsyncTestCase):
    def setUp(self):
        self.profile = InMemoryProfile.test_profile()
        self.context = self.profile.context

        Ledger = async_mock.MagicMock(BaseLedger, autospec=True)
        self.ledger = Ledger()
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value={"value": {"revocation": True}}
        )
        self.ledger.get_revoc_reg_def = async_mock.CoroutineMock()
        self.context.injector.bind_instance(BaseLedger, self.ledger)

        self.revoc = IndyRevocation(self.profile)

        self.test_did = "sample-did"

    async def test_init_issuer_registry(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        result = await self.revoc.init_issuer_registry(CRED_DEF_ID)

        assert result.cred_def_id == CRED_DEF_ID
        assert result.issuer_did == self.test_did
        assert result.max_cred_num == DEFAULT_REGISTRY_SIZE
        assert result.revoc_def_type == IssuerRevRegRecord.REVOC_DEF_TYPE_CL
        assert result.tag is None

    async def test_init_issuer_registry_no_cred_def(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        self.profile.context.injector.clear_binding(BaseLedger)
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value=None
        )
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(RevocationNotSupportedError) as x_revo:
            await self.revoc.init_issuer_registry(CRED_DEF_ID)
            assert x_revo.message == "Credential definition not found"

    async def test_init_issuer_registry_bad_size(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        self.profile.context.injector.clear_binding(BaseLedger)
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value={"value": {"revocation": "..."}}
        )
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(RevocationRegistryBadSizeError) as x_revo:
            await self.revoc.init_issuer_registry(
                CRED_DEF_ID,
                max_cred_num=1,
            )
            assert "Bad revocation registry size" in x_revo.message

    async def test_get_active_issuer_rev_reg_record(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"
        rec = await self.revoc.init_issuer_registry(CRED_DEF_ID)
        rec.revoc_reg_id = "dummy"
        rec.state = IssuerRevRegRecord.STATE_ACTIVE

        async with self.profile.session() as session:
            await rec.save(session)

        result = await self.revoc.get_active_issuer_rev_reg_record(CRED_DEF_ID)
        assert rec == result

    async def test_get_active_issuer_rev_reg_record_none(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"
        with self.assertRaises(StorageNotFoundError) as x_init:
            await self.revoc.get_active_issuer_rev_reg_record(CRED_DEF_ID)

    async def test_init_issuer_registry_no_revocation(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        self.profile.context.injector.clear_binding(BaseLedger)
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value={"value": {}}
        )
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(RevocationNotSupportedError) as x_revo:
            await self.revoc.init_issuer_registry(CRED_DEF_ID)
            assert x_revo.message == "Credential definition does not support revocation"

    async def test_get_issuer_rev_reg_record(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        rec = await self.revoc.init_issuer_registry(CRED_DEF_ID)
        rec.revoc_reg_id = "dummy"
        rec.generate_registry = async_mock.CoroutineMock()

        with async_mock.patch.object(
            IssuerRevRegRecord, "retrieve_by_revoc_reg_id", async_mock.CoroutineMock()
        ) as mock_retrieve_by_rr_id:
            mock_retrieve_by_rr_id.return_value = rec
            await rec.generate_registry(self.profile, None)

            result = await self.revoc.get_issuer_rev_reg_record(rec.revoc_reg_id)
            assert result.revoc_reg_id == "dummy"

    async def test_list_issuer_registries(self):
        CRED_DEF_ID = [f"{self.test_did}:3:CL:{i}:default" for i in (1234, 5678)]

        for cd_id in CRED_DEF_ID:
            rec = await self.revoc.init_issuer_registry(cd_id)

        assert len(await self.revoc.list_issuer_registries()) == 2

    async def test_get_ledger_registry(self):
        CRED_DEF_ID = "{self.test_did}:3:CL:1234:default"

        with async_mock.patch.object(
            RevocationRegistry, "from_definition", async_mock.MagicMock()
        ) as mock_from_def:
            result = await self.revoc.get_ledger_registry("dummy")
            assert result == mock_from_def.return_value
            assert "dummy" in IndyRevocation.REV_REG_CACHE

            await self.revoc.get_ledger_registry("dummy")

        mock_from_def.assert_called_once_with(
            self.ledger.get_revoc_reg_def.return_value, True
        )
