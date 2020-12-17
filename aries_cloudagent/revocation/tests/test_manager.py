import json

from asynctest import mock as async_mock
from asynctest import TestCase as AsyncTestCase

from ...core.in_memory import InMemoryProfile
from ...indy.issuer import IndyIssuer
from ...protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange,
)

from ..manager import RevocationManager, RevocationManagerError

from .. import manager as test_module

TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "bc-reg"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:tag1"
REV_REG_ID = f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag1"
TAILS_DIR = "/tmp/indy/revocation/tails_files"
TAILS_HASH = "8UW1Sz5cqoUnK9hqQk7nvtKK65t7Chu3ui866J23sFyJ"
TAILS_LOCAL = f"{TAILS_DIR}/{TAILS_HASH}"


class TestRevocationManager(AsyncTestCase):
    async def setUp(self):
        self.profile = InMemoryProfile.test_profile()
        self.manager = RevocationManager(self.profile)

    async def test_revoke_credential_publish(self):
        CRED_EX_ID = "dummy-cxid"
        CRED_REV_ID = "1"
        with async_mock.patch.object(
            test_module.IssuerCredRevRecord,
            "retrieve_by_cred_ex_id",
            async_mock.CoroutineMock(),
        ) as mock_retrieve, async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc:
            mock_retrieve.return_value = async_mock.MagicMock(
                rev_reg_id="dummy-rr-id", cred_rev_id=CRED_REV_ID
            )
            mock_issuer_rev_reg_record = async_mock.MagicMock(
                revoc_reg_id=REV_REG_ID,
                tails_local_path=TAILS_LOCAL,
                send_entry=async_mock.CoroutineMock(),
                clear_pending=async_mock.CoroutineMock(),
            )
            mock_rev_reg = async_mock.MagicMock(
                get_or_fetch_local_tails_path=async_mock.CoroutineMock()
            )
            revoc.return_value.get_issuer_rev_reg_record = async_mock.CoroutineMock(
                return_value=mock_issuer_rev_reg_record
            )
            revoc.return_value.get_ledger_registry = async_mock.CoroutineMock(
                return_value=mock_rev_reg
            )

            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            issuer.revoke_credentials = async_mock.CoroutineMock(
                return_value=(
                    json.dumps(
                        {
                            "ver": "1.0",
                            "value": {
                                "prevAccum": "1 ...",
                                "accum": "21 ...",
                                "issued": [1],
                            },
                        }
                    ),
                    [],
                )
            )
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            await self.manager.revoke_credential_by_cred_ex_id(CRED_EX_ID, publish=True)

    async def test_revoke_cred_by_cxid_not_found(self):
        CRED_EX_ID = "dummy-cxid"
        CRED_REV_ID = "1"

        with async_mock.patch.object(
            test_module.IssuerCredRevRecord,
            "retrieve_by_cred_ex_id",
            async_mock.CoroutineMock(),
        ) as mock_retrieve:
            mock_retrieve.side_effect = test_module.StorageNotFoundError("no such rec")

            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            with self.assertRaises(RevocationManagerError):
                await self.manager.revoke_credential_by_cred_ex_id(CRED_EX_ID)

    async def test_revoke_credential_no_rev_reg_rec(self):
        CRED_REV_ID = "1"
        exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_definition_id=CRED_DEF_ID,
            role=V10CredentialExchange.ROLE_ISSUER,
            revocation_id=CRED_REV_ID,
            revoc_reg_id=REV_REG_ID,
        )

        with async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc:
            revoc.return_value.get_issuer_rev_reg_record = async_mock.CoroutineMock(
                return_value=None
            )

            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            with self.assertRaises(RevocationManagerError):
                await self.manager.revoke_credential(REV_REG_ID, CRED_REV_ID)

    async def test_revoke_credential_pend(self):
        CRED_REV_ID = "1"
        with async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc, async_mock.patch.object(
            self.profile,
            "session",
            async_mock.MagicMock(return_value=self.profile.session()),
        ) as session:
            mock_issuer_rev_reg_record = async_mock.MagicMock(
                mark_pending=async_mock.CoroutineMock()
            )
            revoc.return_value.get_issuer_rev_reg_record = async_mock.CoroutineMock(
                return_value=mock_issuer_rev_reg_record
            )

            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            await self.manager.revoke_credential(REV_REG_ID, CRED_REV_ID, False)
            mock_issuer_rev_reg_record.mark_pending.assert_called_once_with(
                session.return_value, CRED_REV_ID
            )

    async def test_publish_pending_revocations(self):
        deltas = [
            {
                "ver": "1.0",
                "value": {"prevAccum": "1 ...", "accum": "21 ...", "issued": [1, 2, 3]},
            },
            {
                "ver": "1.0",
                "value": {
                    "prevAccum": "21 ...",
                    "accum": "36 ...",
                    "issued": [1, 2, 3],
                },
            },
        ]

        mock_issuer_rev_reg_record = async_mock.MagicMock(
            revoc_reg_id=REV_REG_ID,
            tails_local_path=TAILS_LOCAL,
            pending_pub=["1", "2"],
            send_entry=async_mock.CoroutineMock(),
            clear_pending=async_mock.CoroutineMock(),
        )
        with async_mock.patch.object(
            test_module.IssuerRevRegRecord,
            "query_by_pending",
            async_mock.CoroutineMock(return_value=[mock_issuer_rev_reg_record]),
        ) as record_query:
            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            issuer.merge_revocation_registry_deltas = async_mock.CoroutineMock(
                side_effect=deltas
            )

            issuer.revoke_credentials = async_mock.CoroutineMock(
                side_effect=[(json.dumps(delta), []) for delta in deltas]
            )
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            result = await self.manager.publish_pending_revocations()
            assert result == {REV_REG_ID: ["1", "2"]}
            mock_issuer_rev_reg_record.clear_pending.assert_called_once()

    async def test_publish_pending_revocations_1_rev_reg_all(self):
        deltas = [
            {
                "ver": "1.0",
                "value": {"prevAccum": "1 ...", "accum": "21 ...", "issued": [1, 2, 3]},
            },
            {
                "ver": "1.0",
                "value": {
                    "prevAccum": "21 ...",
                    "accum": "36 ...",
                    "issued": [1, 2, 3],
                },
            },
        ]

        mock_issuer_rev_reg_records = [
            async_mock.MagicMock(
                revoc_reg_id=REV_REG_ID,
                tails_local_path=TAILS_LOCAL,
                pending_pub=["1", "2"],
                send_entry=async_mock.CoroutineMock(),
                clear_pending=async_mock.CoroutineMock(),
            ),
            async_mock.MagicMock(
                revoc_reg_id=f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag2",
                tails_local_path=TAILS_LOCAL,
                pending_pub=["9", "99"],
                send_entry=async_mock.CoroutineMock(),
                clear_pending=async_mock.CoroutineMock(),
            ),
        ]
        with async_mock.patch.object(
            test_module.IssuerRevRegRecord,
            "query_by_pending",
            async_mock.CoroutineMock(return_value=mock_issuer_rev_reg_records),
        ) as record:
            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            issuer.merge_revocation_registry_deltas = async_mock.CoroutineMock(
                side_effect=deltas
            )

            issuer.revoke_credentials = async_mock.CoroutineMock(
                side_effect=[(json.dumps(delta), []) for delta in deltas]
            )
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            result = await self.manager.publish_pending_revocations({REV_REG_ID: None})
            assert result == {REV_REG_ID: ["1", "2"]}
            mock_issuer_rev_reg_records[0].clear_pending.assert_called_once()
            mock_issuer_rev_reg_records[1].clear_pending.assert_not_called()

    async def test_publish_pending_revocations_1_rev_reg_some(self):
        deltas = [
            {
                "ver": "1.0",
                "value": {"prevAccum": "1 ...", "accum": "21 ...", "issued": [1, 2, 3]},
            },
            {
                "ver": "1.0",
                "value": {
                    "prevAccum": "21 ...",
                    "accum": "36 ...",
                    "issued": [1, 2, 3],
                },
            },
        ]

        mock_issuer_rev_reg_records = [
            async_mock.MagicMock(
                revoc_reg_id=REV_REG_ID,
                tails_local_path=TAILS_LOCAL,
                pending_pub=["1", "2"],
                send_entry=async_mock.CoroutineMock(),
                clear_pending=async_mock.CoroutineMock(),
            ),
            async_mock.MagicMock(
                revoc_reg_id=f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag2",
                tails_local_path=TAILS_LOCAL,
                pending_pub=["9", "99"],
                send_entry=async_mock.CoroutineMock(),
                clear_pending=async_mock.CoroutineMock(),
            ),
        ]
        with async_mock.patch.object(
            test_module.IssuerRevRegRecord,
            "query_by_pending",
            async_mock.CoroutineMock(return_value=mock_issuer_rev_reg_records),
        ) as record:
            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            issuer.merge_revocation_registry_deltas = async_mock.CoroutineMock(
                side_effect=deltas
            )

            issuer.revoke_credentials = async_mock.CoroutineMock(
                side_effect=[(json.dumps(delta), []) for delta in deltas]
            )
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            result = await self.manager.publish_pending_revocations({REV_REG_ID: "2"})
            assert result == {REV_REG_ID: ["2"]}
            mock_issuer_rev_reg_records[0].clear_pending.assert_called_once()
            mock_issuer_rev_reg_records[1].clear_pending.assert_not_called()

    async def test_clear_pending(self):
        mock_issuer_rev_reg_records = [
            async_mock.MagicMock(
                revoc_reg_id=REV_REG_ID,
                tails_local_path=TAILS_LOCAL,
                pending_pub=[],
                clear_pending=async_mock.CoroutineMock(),
            ),
            async_mock.MagicMock(
                revoc_reg_id=f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag2",
                tails_local_path=TAILS_LOCAL,
                pending_pub=[],
                clear_pending=async_mock.CoroutineMock(),
            ),
        ]
        with async_mock.patch.object(
            test_module.IssuerRevRegRecord,
            "query_by_pending",
            async_mock.CoroutineMock(return_value=mock_issuer_rev_reg_records),
        ) as record:
            result = await self.manager.clear_pending_revocations()
            assert result == {}

    async def test_clear_pending_1_rev_reg_all(self):
        mock_issuer_rev_reg_records = [
            async_mock.MagicMock(
                revoc_reg_id=REV_REG_ID,
                tails_local_path=TAILS_LOCAL,
                pending_pub=["1", "2"],
                clear_pending=async_mock.CoroutineMock(),
            ),
            async_mock.MagicMock(
                revoc_reg_id=f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag2",
                tails_local_path=TAILS_LOCAL,
                pending_pub=["9", "99"],
                clear_pending=async_mock.CoroutineMock(),
            ),
        ]
        with async_mock.patch.object(
            test_module.IssuerRevRegRecord,
            "query_by_pending",
            async_mock.CoroutineMock(return_value=mock_issuer_rev_reg_records),
        ) as record:
            result = await self.manager.clear_pending_revocations({REV_REG_ID: None})
            assert result == {
                REV_REG_ID: ["1", "2"],
                f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag2": ["9", "99"],
            }

    async def test_clear_pending_1_rev_reg_some(self):
        mock_issuer_rev_reg_records = [
            async_mock.MagicMock(
                revoc_reg_id=REV_REG_ID,
                tails_local_path=TAILS_LOCAL,
                pending_pub=["1", "2"],
                clear_pending=async_mock.CoroutineMock(),
            ),
            async_mock.MagicMock(
                revoc_reg_id=f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag2",
                tails_local_path=TAILS_LOCAL,
                pending_pub=["99"],
                clear_pending=async_mock.CoroutineMock(),
            ),
        ]
        with async_mock.patch.object(
            test_module.IssuerRevRegRecord,
            "query_by_pending",
            async_mock.CoroutineMock(return_value=mock_issuer_rev_reg_records),
        ) as record:
            result = await self.manager.clear_pending_revocations({REV_REG_ID: ["9"]})
            assert result == {
                REV_REG_ID: ["1", "2"],
                f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:tag2": ["99"],
            }

    async def test_retrieve_records(self):
        session = await self.profile.session()
        for index in range(2):
            exchange_record = V10CredentialExchange(
                connection_id=str(index),
                thread_id=str(1000 + index),
                initiator=V10CredentialExchange.INITIATOR_SELF,
                role=V10CredentialExchange.ROLE_ISSUER,
            )
            await exchange_record.save(session)

        for i in range(2):  # second pass gets from cache
            for index in range(2):
                ret_ex = await V10CredentialExchange.retrieve_by_connection_and_thread(
                    session, str(index), str(1000 + index)
                )
                assert ret_ex.connection_id == str(index)
                assert ret_ex.thread_id == str(1000 + index)
