import asyncio
import json
from collections import OrderedDict
from copy import deepcopy
from unittest import IsolatedAsyncioTestCase

import pytest

from ....cache.base import BaseCache
from ....cache.in_memory import InMemoryCache
from ....ledger.base import BaseLedger
from ....messaging.responder import BaseResponder
from ....tests import mock
from ....utils.testing import create_test_profile
from ...error import LedgerError
from ...indy_vdr import IndyVdrLedger, IndyVdrLedgerPool
from ...merkel_validation.tests.test_data import GET_NYM_REPLY
from .. import indy_vdr_manager as test_module
from ..base_manager import MultipleLedgerManagerError
from ..indy_vdr_manager import MultiIndyVDRLedgerManager

GET_NYM_INDY_VDR_REPLY = {
    "data": {
        "dest": "Av63wJYM7xYR4AiygYq4c3",
        "identifier": "V4SGRU86Z58d6TV7PBUe6f",
        "role": "101",
        "seqNo": 17794,
        "txnTime": 1632262244,
        "verkey": "6QSduYdf8Bi6t8PfNm5vNomGWDtXhmMmTRzaciudBXYJ",
    },
    "dest": "Av63wJYM7xYR4AiygYq4c3",
    "identifier": "LibindyDid111111111111",
    "reqId": 1632267113185021500,
    "seqNo": 17794,
    "state_proof": {
        "multi_signature": {
            "participants": ["Node2", "Node3", "Node1"],
            "signature": "Qye7WDGrhwEpr2MUmQ2hhm8yWAsUG6gKKf4TXxrw7BybGA96HWXLXhnV5gm5HBQCb4sDXiirTKuyWgMDyfDxKewya9mZhkGXf5WzaADFuaoJkTeSywqqmsrfpcHc2e49eEyncpCxFzhJn6sius4jLgJ7MAfSeVGwyydeR1YsJb3Nm5",
            "value": {
                "ledger_id": 1,
                "pool_state_root_hash": "7siDH8Qanh82UviK4zjBSfLXcoCvLaeGkrByi1ow9Tsm",
                "state_root_hash": "GJq4XL4pJYnDGg3MJ64y3QnfuezxsuBEezk5GC5yaZPM",
                "timestamp": 1632266842,
                "txn_root_hash": "BTnnWQ7imcHSoMykHLeYZX5q8eGEHWdbUydQNA4RG8La",
            },
        },
        "proof_nodes": r"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",
        "root_hash": "GJq4XL4pJYnDGg3MJ64y3QnfuezxsuBEezk5GC5yaZPM",
    },
    "txnTime": 1632262244,
    "type": "105",
}


@pytest.mark.indy_vdr
class TestMultiIndyVDRLedgerManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(BaseCache, InMemoryCache())
        self.context = self.profile.context
        setattr(self.context, "profile", self.profile)
        self.responder = mock.CoroutineMock(send=mock.CoroutineMock())
        self.context.injector.bind_instance(BaseResponder, self.responder)
        self.production_ledger = OrderedDict()
        self.non_production_ledger = OrderedDict()
        test_prod_ledger = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_prod_1"), self.profile
        )
        writable_ledgers = set()
        self.production_ledger["test_prod_1"] = test_prod_ledger
        self.production_ledger["test_prod_2"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_prod_2"), self.profile
        )
        self.non_production_ledger["test_non_prod_1"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_1"), self.profile
        )
        self.non_production_ledger["test_non_prod_2"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_2"), self.profile
        )
        writable_ledgers.add("test_prod_1")
        writable_ledgers.add("test_prod_2")
        self.manager = MultiIndyVDRLedgerManager(
            self.profile,
            production_ledgers=self.production_ledger,
            non_production_ledgers=self.non_production_ledger,
            writable_ledgers=writable_ledgers,
        )

    def test_get_endorser_info_for_ledger(self):
        writable_ledgers = set()
        writable_ledgers.add("test_prod_1")
        writable_ledgers.add("test_prod_2")

        endorser_info_map = {}
        endorser_info_map["test_prod_1"] = {
            "endorser_did": "test_public_did_1",
            "endorser_alias": "endorser_1",
        }
        endorser_info_map["test_prod_2"] = {
            "endorser_did": "test_public_did_2",
            "endorser_alias": "endorser_2",
        }
        manager = MultiIndyVDRLedgerManager(
            self.profile,
            production_ledgers=self.production_ledger,
            non_production_ledgers=self.non_production_ledger,
            writable_ledgers=writable_ledgers,
            endorser_map=endorser_info_map,
        )
        endorser_info_1 = manager.get_endorser_info_for_ledger("test_prod_1")
        assert endorser_info_1 == ("endorser_1", "test_public_did_1")

        endorser_info_2 = manager.get_endorser_info_for_ledger("test_prod_2")
        assert endorser_info_2 == ("endorser_2", "test_public_did_2")

    async def test_get_write_ledgers(self):
        ledger_ids = await self.manager.get_write_ledgers()
        assert "test_prod_1" in ledger_ids
        assert "test_prod_2" in ledger_ids

    async def test_get_write_ledger_from_base_ledger(self):
        ledger_id = await self.manager.get_ledger_id_by_ledger_pool_name("test_prod_1")
        assert ledger_id == "test_prod_1"

    async def test_set_profile_write_ledger(self):
        writable_ledgers = set()
        writable_ledgers.add("test_prod_1")
        writable_ledgers.add("test_prod_2")
        endorser_info_map = {}
        endorser_info_map["test_prod_2"] = {
            "endorser_did": "test_public_did_2",
            "endorser_alias": "endorser_2",
        }
        manager = MultiIndyVDRLedgerManager(
            self.profile,
            production_ledgers=self.production_ledger,
            non_production_ledgers=self.non_production_ledger,
            writable_ledgers=writable_ledgers,
            endorser_map=endorser_info_map,
        )
        self.profile = await create_test_profile()
        assert not self.profile.inject_or(BaseLedger)
        assert "test_prod_2" in manager.writable_ledgers
        new_write_ledger_id = await manager.set_profile_write_ledger(
            profile=self.profile, ledger_id="test_prod_2"
        )
        assert new_write_ledger_id == "test_prod_2"
        new_write_ledger = self.profile.inject_or(BaseLedger)
        assert new_write_ledger.pool_name == "test_prod_2"

    async def test_set_profile_write_ledger_x(self):
        self.profile = await create_test_profile()
        with self.assertRaises(MultipleLedgerManagerError) as cm:
            await self.manager.set_profile_write_ledger(
                profile=self.profile, ledger_id="test_non_prod_1"
            )
        assert "is not write configurable" in str(cm.exception.message)

    async def test_get_ledger_inst_by_id(self):
        ledger_inst = await self.manager.get_ledger_inst_by_id("test_prod_2")
        assert ledger_inst
        ledger_inst = await self.manager.get_ledger_inst_by_id("test_non_prod_2")
        assert ledger_inst
        ledger_inst = await self.manager.get_ledger_inst_by_id("test_invalid")
        assert not ledger_inst

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_self_cert_a(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        with mock.patch.object(
            test_module.asyncio, "wait", mock.CoroutineMock()
        ) as mock_wait:
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = json.dumps(GET_NYM_INDY_VDR_REPLY)
            mock_wait.return_value = mock_submit.return_value
            (
                ledger_id,
                ledger_inst,
                is_self_certified,
            ) = await self.manager._get_ledger_by_did(
                "test_prod_1", "Av63wJYM7xYR4AiygYq4c3"
            )
            assert ledger_id == "test_prod_1"
            assert ledger_inst.pool.name == "test_prod_1"
            assert is_self_certified

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_self_cert_b(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        self.non_production_ledger = OrderedDict()
        self.non_production_ledger["test_non_prod_1"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_1"), self.profile
        )
        self.non_production_ledger["test_non_prod_2"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_2"), self.profile
        )
        self.manager = MultiIndyVDRLedgerManager(
            self.profile,
            non_production_ledgers=self.non_production_ledger,
        )
        with mock.patch.object(
            test_module.asyncio, "wait", mock.CoroutineMock()
        ) as mock_wait:
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = json.dumps(GET_NYM_INDY_VDR_REPLY)
            mock_wait.return_value = mock_submit.return_value
            (
                ledger_id,
                ledger_inst,
                is_self_certified,
            ) = await self.manager._get_ledger_by_did(
                "test_non_prod_1", "Av63wJYM7xYR4AiygYq4c3"
            )
            assert ledger_id == "test_non_prod_1"
            assert ledger_inst.pool.name == "test_non_prod_1"
            assert is_self_certified

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_not_self_cert(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        get_nym_reply = deepcopy(GET_NYM_INDY_VDR_REPLY)
        get_nym_reply["data"] = json.dumps(
            {
                "dest": "Av63wJYM7xYR4AiygYq4c3",
                "identifier": "V4SGRU86Z58d6TV7PBUe6f",
                "role": "101",
                "seqNo": 17794,
                "txnTime": 1632262244,
                "verkey": "ABUF7uxYTxZ6qYdZ4G9e1Gi",
            }
        )
        with (
            mock.patch.object(
                test_module.asyncio, "wait", mock.CoroutineMock()
            ) as mock_wait,
            mock.patch.object(
                test_module.SubTrie, "verify_spv_proof", mock.CoroutineMock()
            ) as mock_verify_spv_proof,
        ):
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = get_nym_reply
            mock_wait.return_value = mock_submit.return_value
            mock_verify_spv_proof.return_value = True
            (
                ledger_id,
                ledger_inst,
                is_self_certified,
            ) = await self.manager._get_ledger_by_did(
                "test_prod_1", "Av63wJYM7xYR4AiygYq4c3"
            )
            assert ledger_id == "test_prod_1"
            assert ledger_inst.pool.name == "test_prod_1"
            assert not is_self_certified

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_state_proof_not_valid(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        get_nym_reply = deepcopy(GET_NYM_REPLY)
        get_nym_reply["result"]["data"]["verkey"] = "ABUF7uxYTxZ6qYdZ4G9e1Gi"
        with mock.patch.object(
            test_module.asyncio, "wait", mock.CoroutineMock()
        ) as mock_wait:
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = json.dumps(get_nym_reply)
            mock_wait.return_value = mock_submit.return_value
            assert not await self.manager._get_ledger_by_did(
                "test_prod_1", "Av63wJYM7xYR4AiygYq4c3"
            )

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_no_data(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        get_nym_reply = deepcopy(GET_NYM_INDY_VDR_REPLY)
        get_nym_reply.pop("data")
        with mock.patch.object(
            test_module.asyncio, "wait", mock.CoroutineMock()
        ) as mock_wait:
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = get_nym_reply
            mock_wait.return_value = mock_submit.return_value
            assert not await self.manager._get_ledger_by_did(
                "test_prod_1", "Av63wJYM7xYR4AiygYq4c3"
            )

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_timeout(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        mock_build_get_nym_req.return_value = mock.MagicMock()
        mock_submit.side_effect = asyncio.TimeoutError
        assert not await self.manager._get_ledger_by_did(
            "test_prod_1", "Av63wJYM7xYR4AiygYq4c3"
        )

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_ledger_error(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        mock_build_get_nym_req.return_value = mock.MagicMock()
        mock_submit.side_effect = LedgerError
        assert not await self.manager._get_ledger_by_did(
            "test_prod_1", "Av63wJYM7xYR4AiygYq4c3"
        )

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_lookup_did_in_configured_ledgers_self_cert_prod(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        with mock.patch.object(
            test_module.asyncio, "wait", mock.CoroutineMock()
        ) as mock_wait:
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = json.dumps(GET_NYM_INDY_VDR_REPLY)
            mock_wait.return_value = mock_submit.return_value
            (
                ledger_id,
                ledger_inst,
            ) = await self.manager.lookup_did_in_configured_ledgers(
                "Av63wJYM7xYR4AiygYq4c3", cache_did=True
            )
            assert ledger_id == "test_prod_1"
            assert ledger_inst.pool.name == "test_prod_1"

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_not_self_cert_not_self_cert_prod(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        get_nym_reply = deepcopy(GET_NYM_INDY_VDR_REPLY)
        get_nym_reply["data"]["verkey"] = "ABUF7uxYTxZ6qYdZ4G9e1Gi"
        with (
            mock.patch.object(
                test_module.asyncio, "wait", mock.CoroutineMock()
            ) as mock_wait,
            mock.patch.object(
                test_module.SubTrie, "verify_spv_proof", mock.CoroutineMock()
            ) as mock_verify_spv_proof,
        ):
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = get_nym_reply
            mock_wait.return_value = mock_submit.return_value
            mock_verify_spv_proof.return_value = True
            (
                ledger_id,
                ledger_inst,
            ) = await self.manager.lookup_did_in_configured_ledgers(
                "Av63wJYM7xYR4AiygYq4c3", cache_did=True
            )
            assert ledger_id == "test_prod_1"
            assert ledger_inst.pool.name == "test_prod_1"

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_lookup_did_in_configured_ledgers_self_cert_non_prod(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        self.non_production_ledger = OrderedDict()
        self.non_production_ledger["test_non_prod_1"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_1"), self.profile
        )
        self.non_production_ledger["test_non_prod_2"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_2"), self.profile
        )
        self.manager = MultiIndyVDRLedgerManager(
            self.profile,
            non_production_ledgers=self.non_production_ledger,
        )
        with mock.patch.object(
            test_module.asyncio, "wait", mock.CoroutineMock()
        ) as mock_wait:
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = GET_NYM_INDY_VDR_REPLY
            mock_wait.return_value = mock_submit.return_value
            (
                ledger_id,
                ledger_inst,
            ) = await self.manager.lookup_did_in_configured_ledgers(
                "Av63wJYM7xYR4AiygYq4c3", cache_did=True
            )
            assert ledger_id == "test_non_prod_1"
            assert ledger_inst.pool.name == "test_non_prod_1"

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_get_ledger_by_did_not_self_cert_non_prod(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        self.non_production_ledger = OrderedDict()
        self.non_production_ledger["test_non_prod_1"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_1"), self.profile
        )
        self.non_production_ledger["test_non_prod_2"] = IndyVdrLedger(
            await IndyVdrLedgerPool.get_or_create(name="test_non_prod_2"), self.profile
        )
        self.manager = MultiIndyVDRLedgerManager(
            self.profile,
            non_production_ledgers=self.non_production_ledger,
        )
        get_nym_reply = deepcopy(GET_NYM_REPLY)
        get_nym_reply["result"]["data"]["verkey"] = "ABUF7uxYTxZ6qYdZ4G9e1Gi"
        with (
            mock.patch.object(
                test_module.asyncio, "wait", mock.CoroutineMock()
            ) as mock_wait,
            mock.patch.object(
                test_module.SubTrie, "verify_spv_proof", mock.CoroutineMock()
            ) as mock_verify_spv_proof,
        ):
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = get_nym_reply
            mock_wait.return_value = mock_submit.return_value
            mock_verify_spv_proof.return_value = True
            (
                ledger_id,
                ledger_inst,
            ) = await self.manager.lookup_did_in_configured_ledgers(
                "Av63wJYM7xYR4AiygYq4c3", cache_did=True
            )
            assert ledger_id == "test_non_prod_1"
            assert ledger_inst.pool.name == "test_non_prod_1"

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_lookup_did_in_configured_ledgers_x(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        with (
            mock.patch.object(
                test_module.asyncio, "wait", mock.CoroutineMock()
            ) as mock_wait,
            mock.patch.object(
                test_module.SubTrie, "verify_spv_proof", mock.CoroutineMock()
            ) as mock_verify_spv_proof,
        ):
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = GET_NYM_INDY_VDR_REPLY
            mock_wait.return_value = mock_submit.return_value
            mock_verify_spv_proof.return_value = False
            with self.assertRaises(MultipleLedgerManagerError):
                await self.manager.lookup_did_in_configured_ledgers(
                    "Av63wJYM7xYR4AiygYq4c3", cache_did=True
                )

    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_open")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedgerPool.context_close")
    @mock.patch("indy_vdr.ledger.build_get_nym_request")
    @mock.patch("acapy_agent.ledger.indy_vdr.IndyVdrLedger._submit")
    async def test_lookup_did_in_configured_ledgers_prod_not_cached(
        self, mock_submit, mock_build_get_nym_req, mock_close, mock_open
    ):
        with mock.patch.object(
            test_module.asyncio, "wait", mock.CoroutineMock()
        ) as mock_wait:
            mock_build_get_nym_req.return_value = mock.MagicMock()
            mock_submit.return_value = GET_NYM_INDY_VDR_REPLY
            mock_wait.return_value = mock_submit.return_value
            (
                ledger_id,
                ledger_inst,
            ) = await self.manager.lookup_did_in_configured_ledgers(
                "Av63wJYM7xYR4AiygYq4c3", cache_did=False
            )
            assert ledger_id == "test_prod_1"
            assert ledger_inst.pool.name == "test_prod_1"

    async def test_lookup_did_in_configured_ledgers_cached_prod_ledger(self):
        cache = InMemoryCache()
        await cache.set("did_ledger_id_resolver::Av63wJYM7xYR4AiygYq4c3", "test_prod_1")
        self.profile.context.injector.bind_instance(BaseCache, cache)
        (
            ledger_id,
            ledger_inst,
        ) = await self.manager.lookup_did_in_configured_ledgers(
            "Av63wJYM7xYR4AiygYq4c3", cache_did=True
        )
        assert ledger_id == "test_prod_1"
        assert ledger_inst.pool.name == "test_prod_1"

    async def test_lookup_did_in_configured_ledgers_cached_non_prod_ledger(self):
        cache = InMemoryCache()
        await cache.set(
            "did_ledger_id_resolver::Av63wJYM7xYR4AiygYq4c3", "test_non_prod_2", None
        )
        self.profile.context.injector.bind_instance(BaseCache, cache)
        (
            ledger_id,
            ledger_inst,
        ) = await self.manager.lookup_did_in_configured_ledgers(
            "Av63wJYM7xYR4AiygYq4c3", cache_did=True
        )
        assert ledger_id == "test_non_prod_2"
        assert ledger_inst.pool.name == "test_non_prod_2"

    async def test_lookup_did_in_configured_ledgers_cached_x(self):
        cache = InMemoryCache()
        await cache.set("did_ledger_id_resolver::Av63wJYM7xYR4AiygYq4c3", "invalid_id")
        self.profile.context.injector.bind_instance(BaseCache, cache)
        with self.assertRaises(MultipleLedgerManagerError):
            await self.manager.lookup_did_in_configured_ledgers(
                "Av63wJYM7xYR4AiygYq4c3", cache_did=True
            )

    async def test_get_production_ledgers(self):
        assert len(await self.manager.get_prod_ledgers()) == 2

    async def test_get_non_production_ledgers(self):
        assert len(await self.manager.get_nonprod_ledgers()) == 2
