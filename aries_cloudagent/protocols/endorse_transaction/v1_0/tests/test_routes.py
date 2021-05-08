import json

from asynctest import mock as async_mock, TestCase as AsyncTestCase

from .....admin.request_context import AdminRequestContext
from .....connections.models.conn_record import ConnRecord
from .....core.in_memory import InMemoryProfile
from .....ledger.base import BaseLedger
from .....wallet.did_method import DIDMethod
from .....wallet.key_type import KeyType
from .....wallet.base import BaseWallet
from .....wallet.did_info import DIDInfo

from .. import routes as test_module
from ..models.transaction_record import TransactionRecord


TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "bc-reg"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:tag1"


class TestEndorseTransactionRoutes(AsyncTestCase):
    def setUp(self):
        self.session_inject = {}
        self.profile = InMemoryProfile.test_profile()
        self.profile_injector = self.profile.context.injector

        self.ledger = async_mock.create_autospec(BaseLedger)
        self.ledger.__aenter__ = async_mock.CoroutineMock(return_value=self.ledger)
        self.ledger.txn_endorse = async_mock.CoroutineMock(
            return_value=async_mock.MagicMock()
        )
        self.ledger.txn_submit = async_mock.CoroutineMock(
            return_value=json.dumps(
                {
                    "result": {
                        "txn": {"type": "101", "metadata": {"from": TEST_DID}},
                        "txnMetadata": {"txnId": SCHEMA_ID},
                    }
                }
            )
        )
        self.ledger.get_indy_storage = async_mock.MagicMock(
            return_value=async_mock.MagicMock(add_record=async_mock.CoroutineMock())
        )
        self.ledger.get_schema = async_mock.CoroutineMock(
            return_value={"id": SCHEMA_ID, "...": "..."}
        )
        self.profile_injector.bind_instance(BaseLedger, self.ledger)

        self.context = AdminRequestContext.test_context(
            self.session_inject, profile=self.profile
        )

        self.request_dict = {
            "context": self.context,
            "outbound_message_router": async_mock.CoroutineMock(),
        }
        self.request = async_mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
        )

        self.test_did = "sample-did"

    async def test_transactions_list(self):
        with async_mock.patch.object(
            TransactionRecord, "query", async_mock.CoroutineMock()
        ) as mock_query, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_query.return_value = [
                async_mock.MagicMock(
                    serialize=async_mock.MagicMock(return_value={"...": "..."})
                )
            ]
            await test_module.transactions_list(self.request)

            mock_response.assert_called_once_with({"results": [{"...": "..."}]})

    async def test_transactions_list_x(self):
        with async_mock.patch.object(
            TransactionRecord, "query", async_mock.CoroutineMock()
        ) as mock_query, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_query.side_effect = test_module.StorageError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transactions_list(self.request)

    async def test_transactions_retrieve(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_retrieve, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.transactions_retrieve(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_transactions_retrieve_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_retrieve:
            mock_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transactions_retrieve(self.request)

    async def test_transactions_retrieve_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_retrieve:
            mock_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transactions_retrieve(self.request)

    async def test_transaction_create_request(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_request=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(
                            serialize=async_mock.MagicMock(return_value={"...": "..."})
                        ),
                        async_mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.transaction_create_request(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_transaction_create_request_not_found_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_base_model_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_no_jobs_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_request=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(
                            serialize=async_mock.MagicMock(return_value={"...": "..."})
                        ),
                        async_mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_no_my_job_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_request=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(
                            serialize=async_mock.MagicMock(return_value={"...": "..."})
                        ),
                        async_mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_no_their_job_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_request=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(
                            serialize=async_mock.MagicMock(return_value={"...": "..."})
                        ),
                        async_mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_my_wrong_job_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                        "transaction_my_job": "a suffusion of yellow",
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_create_request(self.request)

    async def test_transaction_create_request_mgr_create_request_x(self):
        self.request.query = {
            "tran_id": "dummy",
        }
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "expires_time": "2021-03-29T05:22:19Z",
            }
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_request=async_mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_create_request(self.request)

    async def test_endorse_transaction_response(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_endorse_response=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(
                            serialize=async_mock.MagicMock(return_value={"...": "..."})
                        ),
                        async_mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.endorse_transaction_response(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_endorse_transaction_response_no_wallet_x(self):
        self.session_inject[BaseWallet] = None
        with self.assertRaises(test_module.web.HTTPForbidden):
            await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_no_endorser_did_info_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(return_value=None)
        )

        with self.assertRaises(test_module.web.HTTPForbidden):
            await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_no_ledger_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.context.injector.clear_binding(BaseLedger)
        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_endorse_response=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(
                            serialize=async_mock.MagicMock(return_value={"...": "..."})
                        ),
                        async_mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_wrong_my_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_ledger_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )
        self.ledger.txn_endorse = async_mock.CoroutineMock(
            side_effect=test_module.LedgerError()
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_endorse_response=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(
                            serialize=async_mock.MagicMock(return_value={"...": "..."})
                        ),
                        async_mock.MagicMock(),
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.endorse_transaction_response(self.request)

    async def test_endorse_transaction_response_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_endorse_response=async_mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.endorse_transaction_response(self.request)

    async def test_refuse_transaction_response(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_refuse_response=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(  # transaction
                            connection_id="dummy",
                            serialize=async_mock.MagicMock(return_value={"...": "..."}),
                        ),
                        async_mock.MagicMock(),  # refused_transaction_response
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.refuse_transaction_response(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_refuse_transaction_response_no_wallet_x(self):
        self.session_inject[BaseWallet] = None
        with self.assertRaises(test_module.web.HTTPForbidden):
            await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_no_endorser_did_info_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(return_value=None)
        )

        with self.assertRaises(test_module.web.HTTPForbidden):
            await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_conn_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_wrong_my_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.refuse_transaction_response(self.request)

    async def test_refuse_transaction_response_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        self.session_inject[BaseWallet] = async_mock.MagicMock(
            get_public_did=async_mock.CoroutineMock(
                return_value=DIDInfo(
                    "did",
                    "verkey",
                    {"meta": "data"},
                    method=DIDMethod.SOV,
                    key_type=KeyType.ED25519,
                )
            )
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                create_refuse_response=async_mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.refuse_transaction_response(self.request)

    async def test_cancel_transaction(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                cancel_transaction=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(  # transaction
                            connection_id="dummy",
                            serialize=async_mock.MagicMock(return_value={"...": "..."}),
                        ),
                        async_mock.MagicMock(),  # refused_transaction_response
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.cancel_transaction(self.request)

            mock_response.assert_called_once_with({"...": "..."})

    async def test_cancel_transaction_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_conn_rec_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_wrong_my_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.cancel_transaction(self.request)

    async def test_cancel_transaction_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                cancel_transaction=async_mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.cancel_transaction(self.request)

    async def test_transaction_resend(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                transaction_resend=async_mock.CoroutineMock(
                    return_value=(
                        async_mock.MagicMock(  # transaction
                            connection_id="dummy",
                            serialize=async_mock.MagicMock(return_value={"...": "..."}),
                        ),
                        async_mock.MagicMock(),  # refused_transaction_response
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )
            await test_module.transaction_resend(self.request)

        mock_response.assert_called_once_with({"...": "..."})

    async def test_transaction_resend_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_conn_rec_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_my_wrong_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                        "transaction_my_job": "a suffusion of yellow",
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_resend(self.request)

    async def test_transaction_resend_txn_mgr_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                transaction_resend=async_mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_resend(self.request)

    async def test_set_endorser_role(self):
        self.request.match_info = {"conn_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                set_transaction_my_job=async_mock.CoroutineMock()
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        )
                    }
                )
            )
            await test_module.set_endorser_role(self.request)

        mock_response.assert_called_once_with(
            {"transaction_my_job": test_module.TransactionJob.TRANSACTION_AUTHOR.name}
        )

    async def test_set_endorser_role_not_found_x(self):
        self.request.match_info = {"conn_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.set_endorser_role(self.request)

    async def test_set_endorser_role_base_model_x(self):
        self.request.match_info = {"conn_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.set_endorser_role(self.request)

    async def test_set_endorser_info(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                ),
                metadata_set=async_mock.CoroutineMock(),
            )
            await test_module.set_endorser_info(self.request)

            mock_response.assert_called_once_with(
                {
                    "transaction_my_job": "TRANSACTION_AUTHOR",
                    "transaction_their_job": "TRANSACTION_ENDORSER",
                    "endorser_did": "did",
                    "endorser_name": "name",
                }
            )

    async def test_set_endorser_info_no_prior_value(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    side_effect=[
                        {
                            "transaction_my_job": (
                                test_module.TransactionJob.TRANSACTION_AUTHOR.name
                            ),
                            "transaction_their_job": (
                                test_module.TransactionJob.TRANSACTION_ENDORSER.name
                            ),
                        },
                        None,
                        {
                            "endorser_did": "did",
                            "endorser_name": "name",
                        },
                    ]
                ),
                metadata_set=async_mock.CoroutineMock(),
            )
            await test_module.set_endorser_info(self.request)

            mock_response.assert_called_once_with(
                {
                    "endorser_did": "did",
                    "endorser_name": "name",
                }
            )

    async def test_set_endorser_info_not_found_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_base_model_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_no_transaction_jobs_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(return_value=None)
            )
            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_no_transaction_my_job_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.set_endorser_info(self.request)

    async def test_set_endorser_info_my_wrong_job_x(self):
        self.request.match_info = {"conn_id": "dummy"}
        self.request.query = {"endorser_did": "did", "endorser_name": "name"}
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                        "transaction_my_job": "a suffusion of yellow",
                    }
                )
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.set_endorser_info(self.request)

    """
    async def test_transaction_write_schema_txn(self):
        self.request.match_info = {"tran_id": "dummy"}
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                complete_transaction=async_mock.CoroutineMock(
                    return_value=async_mock.MagicMock(  # txn record
                        serialize=async_mock.MagicMock(return_value={"...": "..."})
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[
                    {"data": {"json": json.dumps({"message": "attached"})}}
                ],
            )
            await test_module.transaction_write(self.request)
            mock_response.assert_called_once_with({"...": "..."})
    """

    async def test_transaction_write_not_found_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.transaction_write(self.request)

    async def test_transaction_write_base_model_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_txn_rec_retrieve.side_effect = test_module.BaseModelError()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_write(self.request)

    async def test_transaction_write_no_jobs_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(return_value=None)
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_write(self.request)

    async def test_transaction_write_my_wrong_job_x(self):
        self.request.match_info = {"tran_id": "dummy"}

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                        "transaction_my_job": "a suffusion of yellow",
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."})
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_write(self.request)

    async def test_transaction_write_wrong_state_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_CREATED,
                messages_attach=[
                    {"data": {"json": json.dumps({"message": "attached"})}}
                ],
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_write(self.request)

    """
    async def test_transaction_write_no_ledger_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.context.injector.clear_binding(BaseLedger)
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[
                    {"data": {"json": json.dumps({"message": "attached"})}}
                ],
            )
            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.transaction_write(self.request)
    async def test_transaction_write_ledger_txn_submit_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.ledger.txn_submit = async_mock.CoroutineMock(
            side_effect=test_module.LedgerError()
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[
                    {"data": {"json": json.dumps({"message": "attached"})}}
                ],
            )
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_write(self.request)
    async def test_transaction_write_cred_def_txn(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.ledger.txn_submit = async_mock.CoroutineMock(
            return_value=json.dumps(
                {
                    "result": {
                        "txn": {
                            "type": "102",
                            "metadata": {"from": TEST_DID},
                            "data": {"ref": 1000},
                        },
                        "txnMetadata": {"txnId": SCHEMA_ID},
                    }
                }
            )
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                complete_transaction=async_mock.CoroutineMock(
                    return_value=async_mock.MagicMock(  # txn record
                        serialize=async_mock.MagicMock(return_value={"...": "..."})
                    )
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[
                    {"data": {"json": json.dumps({"message": "attached"})}}
                ],
            )
            await test_module.transaction_write(self.request)
            mock_response.assert_called_once_with({"...": "..."})
    async def test_transaction_write_ledger_cred_def_txn_ledger_get_schema_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        self.ledger.txn_submit = async_mock.CoroutineMock(
            return_value=json.dumps(
                {
                    "result": {
                        "txn": {
                            "type": "102",
                            "metadata": {"from": TEST_DID},
                            "data": {"ref": 1000},
                        },
                        "txnMetadata": {"txnId": SCHEMA_ID},
                    }
                }
            )
        )
        self.ledger.get_schema = async_mock.CoroutineMock(
            side_effect=test_module.LedgerError()
        )
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve:
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[
                    {"data": {"json": json.dumps({"message": "attached"})}}
                ],
            )
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_write(self.request)
    """

    async def test_transaction_write_schema_txn_complete_x(self):
        self.request.match_info = {"tran_id": "dummy"}
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve, async_mock.patch.object(
            TransactionRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_txn_rec_retrieve, async_mock.patch.object(
            test_module, "TransactionManager", async_mock.MagicMock()
        ) as mock_txn_mgr:
            mock_txn_mgr.return_value = async_mock.MagicMock(
                complete_transaction=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )
            mock_conn_rec_retrieve.return_value = async_mock.MagicMock(
                metadata_get=async_mock.CoroutineMock(
                    return_value={
                        "transaction_my_job": (
                            test_module.TransactionJob.TRANSACTION_AUTHOR.name
                        ),
                        "transaction_their_job": (
                            test_module.TransactionJob.TRANSACTION_ENDORSER.name
                        ),
                    }
                )
            )
            mock_txn_rec_retrieve.return_value = async_mock.MagicMock(
                serialize=async_mock.MagicMock(return_value={"...": "..."}),
                state=TransactionRecord.STATE_TRANSACTION_ENDORSED,
                messages_attach=[
                    {"data": {"json": json.dumps({"message": "attached"})}}
                ],
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.transaction_write(self.request)

    async def test_register(self):
        mock_app = async_mock.MagicMock()
        mock_app.add_routes = async_mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called_once()

    async def test_post_process_routes(self):
        mock_app = async_mock.MagicMock(_state={"swagger_dict": {"paths": {}}})
        test_module.post_process_routes(mock_app)

        assert "tags" in mock_app._state["swagger_dict"]
