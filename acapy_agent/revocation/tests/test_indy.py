from unittest import IsolatedAsyncioTestCase

from ...ledger.base import BaseLedger
from ...ledger.multiple_ledger.ledger_requests_executor import (
    IndyLedgerRequestsExecutor,
)
from ...multitenant.base import BaseMultitenantManager
from ...multitenant.manager import MultitenantManager
from ...storage.error import StorageNotFoundError
from ...tests import mock
from ...utils.testing import create_test_profile
from ..error import (
    RevocationError,
    RevocationNotSupportedError,
    RevocationRegistryBadSizeError,
)
from ..indy import IndyRevocation
from ..models.issuer_rev_reg_record import DEFAULT_REGISTRY_SIZE, IssuerRevRegRecord
from ..models.revocation_registry import RevocationRegistry


class TestIndyRevocation(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.context = self.profile.context

        self.ledger = mock.MagicMock(BaseLedger, autospec=True)
        self.ledger.get_credential_definition = mock.CoroutineMock(
            return_value={"value": {"revocation": True}}
        )
        self.ledger.get_revoc_reg_def = mock.CoroutineMock()
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)
        mock_executor = mock.MagicMock(IndyLedgerRequestsExecutor, autospec=True)
        mock_executor.get_ledger_for_identifier = mock.CoroutineMock(
            return_value=(None, self.ledger)
        )
        self.profile.context.injector.bind_instance(
            IndyLedgerRequestsExecutor, mock_executor
        )
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

        self.context.injector.bind_instance(
            BaseMultitenantManager,
            mock.MagicMock(MultitenantManager, autospec=True),
        )
        with mock.patch.object(
            IndyLedgerRequestsExecutor,
            "get_ledger_for_identifier",
            mock.CoroutineMock(return_value=(None, self.ledger)),
        ):
            result = await self.revoc.init_issuer_registry(CRED_DEF_ID)
        assert result.cred_def_id == CRED_DEF_ID
        assert result.issuer_did == self.test_did
        assert result.max_cred_num == DEFAULT_REGISTRY_SIZE
        assert result.revoc_def_type == IssuerRevRegRecord.REVOC_DEF_TYPE_CL
        assert result.tag is None

    async def test_init_issuer_registry_no_cred_def(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        self.profile.context.injector.clear_binding(BaseLedger)
        self.ledger.get_credential_definition = mock.CoroutineMock(return_value=None)
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(RevocationNotSupportedError):
            await self.revoc.init_issuer_registry(CRED_DEF_ID)

    async def test_init_issuer_registry_bad_size(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        self.profile.context.injector.clear_binding(BaseLedger)
        self.ledger.get_credential_definition = mock.CoroutineMock(
            return_value={"value": {"revocation": "..."}}
        )
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(RevocationRegistryBadSizeError):
            await self.revoc.init_issuer_registry(
                CRED_DEF_ID,
                max_cred_num=1,
            )

    async def test_get_active_issuer_rev_reg_record(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)
        rec = await self.revoc.init_issuer_registry(CRED_DEF_ID)
        rec.revoc_reg_id = "dummy"
        rec.state = IssuerRevRegRecord.STATE_ACTIVE

        async with self.profile.session() as session:
            await rec.save(session)

        result = await self.revoc.get_active_issuer_rev_reg_record(CRED_DEF_ID)
        assert rec == result

    async def test_get_active_issuer_rev_reg_record_none(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"
        with self.assertRaises(StorageNotFoundError):
            await self.revoc.get_active_issuer_rev_reg_record(CRED_DEF_ID)

    async def test_init_issuer_registry_no_revocation(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        self.profile.context.injector.clear_binding(BaseLedger)
        self.ledger.get_credential_definition = mock.CoroutineMock(
            return_value={"value": {}}
        )
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(RevocationNotSupportedError):
            await self.revoc.init_issuer_registry(CRED_DEF_ID)

    async def test_get_issuer_rev_reg_record(self):
        CRED_DEF_ID = f"{self.test_did}:3:CL:1234:default"

        rec = await self.revoc.init_issuer_registry(CRED_DEF_ID)
        rec.revoc_reg_id = "dummy"
        rec.generate_registry = mock.CoroutineMock()

        with mock.patch.object(
            IssuerRevRegRecord, "retrieve_by_revoc_reg_id", mock.CoroutineMock()
        ) as mock_retrieve_by_rr_id:
            mock_retrieve_by_rr_id.return_value = rec
            await rec.generate_registry(self.profile, None)

            result = await self.revoc.get_issuer_rev_reg_record(rec.revoc_reg_id)
            assert result.revoc_reg_id == "dummy"

    async def test_list_issuer_registries(self):
        CRED_DEF_ID = [f"{self.test_did}:3:CL:{i}:default" for i in (1234, 5678)]

        for cd_id in CRED_DEF_ID:
            await self.revoc.init_issuer_registry(cd_id)

        assert len(await self.revoc.list_issuer_registries()) == 2

    async def test_decommission_issuer_registries(self):
        CRED_DEF_ID = [f"{self.test_did}:3:CL:{i}:default" for i in (4321, 8765)]

        for cd_id in CRED_DEF_ID:
            await self.revoc.init_issuer_registry(cd_id)

        # 2 registries, both in init state (no listener to push into active)
        recs = await self.revoc.list_issuer_registries()
        assert len(recs) == 2

        init_list = list(filter(lambda r: r.state == IssuerRevRegRecord.STATE_INIT, recs))
        assert len(init_list) == 2

        # store the ids to verify they are decommissioned
        rev_reg_ids = [rec.revoc_reg_id for rec in recs if rec.revoc_reg_id]

        # need these to be not init so we can decommission
        async with self.profile.transaction() as txn:
            for rec in recs:
                registry = await IssuerRevRegRecord.retrieve_by_revoc_reg_id(
                    txn, rec.revoc_reg_id, for_update=True
                )
                await registry.set_state(
                    txn,
                    IssuerRevRegRecord.STATE_ACTIVE,
                )
            await txn.commit()

        # still 2 registries, but now active
        recs = await self.revoc.list_issuer_registries()
        assert len(recs) == 2
        active_list = list(
            filter(lambda r: r.state == IssuerRevRegRecord.STATE_ACTIVE, recs)
        )
        assert len(active_list) == 2

        #
        # decommission (active-> decommission, create replacement regs)
        #
        for cd_id in CRED_DEF_ID:
            rec = await self.revoc.decommission_registry(cd_id)

        # four entries, 2 new (init), 2 decommissioned
        recs = await self.revoc.list_issuer_registries()
        assert len(recs) == 4

        # previously active are decommissioned
        decomm_list = list(
            filter(lambda r: r.state == IssuerRevRegRecord.STATE_DECOMMISSIONED, recs)
        )
        assert len(decomm_list) == 2
        decomm_rev_reg_ids = [rec.revoc_reg_id for rec in decomm_list if rec.revoc_reg_id]

        # new ones replacing the decommissioned are in init state
        init_list = list(filter(lambda r: r.state == IssuerRevRegRecord.STATE_INIT, recs))
        assert len(init_list) == 2

        # check that the original rev reg ids are decommissioned
        rev_reg_ids.sort()
        decomm_rev_reg_ids.sort()
        assert rev_reg_ids == decomm_rev_reg_ids

    async def test_get_ledger_registry(self):
        with mock.patch.object(
            RevocationRegistry, "from_definition", mock.MagicMock()
        ) as mock_from_def:
            result = await self.revoc.get_ledger_registry("dummy")
            assert result == mock_from_def.return_value
            assert "dummy" in IndyRevocation.REV_REG_CACHE

            await self.revoc.get_ledger_registry("dummy")

        mock_from_def.assert_called_once_with(
            self.ledger.get_revoc_reg_def.return_value, True
        )

        self.context.injector.bind_instance(
            BaseMultitenantManager,
            mock.MagicMock(MultitenantManager, autospec=True),
        )
        with (
            mock.patch.object(
                IndyLedgerRequestsExecutor,
                "get_ledger_for_identifier",
                mock.CoroutineMock(return_value=(None, self.ledger)),
            ),
            mock.patch.object(
                RevocationRegistry, "from_definition", mock.MagicMock()
            ) as mock_from_def,
        ):
            result = await self.revoc.get_ledger_registry("dummy2")
            assert result == mock_from_def.return_value
            assert "dummy2" in IndyRevocation.REV_REG_CACHE

            await self.revoc.get_ledger_registry("dummy2")

        mock_from_def.assert_called_once_with(
            self.ledger.get_revoc_reg_def.return_value, True
        )

    @mock.patch(
        "acapy_agent.revocation.indy.IndyRevocation.get_active_issuer_rev_reg_record",
        mock.CoroutineMock(
            return_value=mock.MagicMock(
                get_registry=mock.MagicMock(
                    return_value=mock.MagicMock(
                        get_or_fetch_local_tails_path=mock.CoroutineMock(
                            return_value="dummy"
                        )
                    )
                )
            )
        ),
    )
    async def test_get_or_create_active_registry_has_active_registry(self, *_):
        result = await self.revoc.get_or_create_active_registry("cred_def_id")
        assert isinstance(result, tuple)

    @mock.patch(
        "acapy_agent.revocation.indy.IndyRevocation.get_active_issuer_rev_reg_record",
        mock.CoroutineMock(side_effect=StorageNotFoundError("No such record")),
    )
    @mock.patch(
        "acapy_agent.revocation.indy.IndyRevocation.init_issuer_registry",
        mock.CoroutineMock(return_value=None),
    )
    @mock.patch.object(
        IssuerRevRegRecord,
        "query_by_cred_def_id",
        side_effect=[[], [IssuerRevRegRecord(max_cred_num=3)]],
    )
    async def test_get_or_create_active_registry_has_no_active_and_only_full_registies(
        self, *_
    ):
        result = await self.revoc.get_or_create_active_registry("cred_def_id")

        assert not result
        assert self.revoc.init_issuer_registry.call_args.kwargs["max_cred_num"] == 3

    @mock.patch(
        "acapy_agent.revocation.indy.IndyRevocation.get_active_issuer_rev_reg_record",
        mock.CoroutineMock(side_effect=StorageNotFoundError("No such record")),
    )
    @mock.patch(
        "acapy_agent.revocation.indy.IndyRevocation.init_issuer_registry",
        mock.CoroutineMock(return_value=None),
    )
    @mock.patch.object(IssuerRevRegRecord, "query_by_cred_def_id", side_effect=[[], []])
    async def test_get_or_create_active_registry_has_no_active_or_any_registry(self, *_):
        with self.assertRaises(RevocationError):
            await self.revoc.get_or_create_active_registry("cred_def_id")

    @mock.patch(
        "acapy_agent.revocation.indy.IndyRevocation.get_active_issuer_rev_reg_record",
        mock.CoroutineMock(side_effect=StorageNotFoundError("No such record")),
    )
    @mock.patch(
        "acapy_agent.revocation.indy.IndyRevocation._set_registry_status",
        mock.CoroutineMock(return_value=None),
    )
    @mock.patch.object(
        IssuerRevRegRecord,
        "query_by_cred_def_id",
        side_effect=[
            [IssuerRevRegRecord(max_cred_num=3)],
            [
                IssuerRevRegRecord(
                    revoc_reg_id="test-rev-reg-id",
                    state=IssuerRevRegRecord.STATE_POSTED,
                )
            ],
        ],
    )
    async def test_get_or_create_active_registry_has_no_active_with_posted(self, *_):
        result = await self.revoc.get_or_create_active_registry("cred_def_id")

        assert not result
        assert (
            self.revoc._set_registry_status.call_args.kwargs["state"]
            == IssuerRevRegRecord.STATE_ACTIVE
        )
