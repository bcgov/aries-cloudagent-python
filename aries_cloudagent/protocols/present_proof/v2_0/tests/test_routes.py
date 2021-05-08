from copy import deepcopy
from time import time

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock
from marshmallow import ValidationError

from .....admin.request_context import AdminRequestContext
from .....core.in_memory import InMemoryProfile
from .....indy.holder import IndyHolder
from .....indy.sdk.models.proof_request import IndyProofReqAttrSpecSchema
from .....indy.verifier import IndyVerifier
from .....ledger.base import BaseLedger
from .....storage.error import StorageNotFoundError

from .. import routes as test_module
from ..messages.pres_format import V20PresFormat

ISSUER_DID = "NcYxiDXkpYi6ov5FcYDi1e"
S_ID = f"{ISSUER_DID}:2:vidya:1.0"
CD_ID = f"{ISSUER_DID}:3:CL:{S_ID}:tag1"
RR_ID = f"{ISSUER_DID}:4:{CD_ID}:CL_ACCUM:0"
PROOF_REQ_NAME = "name"
PROOF_REQ_VERSION = "1.0"
PROOF_REQ_NONCE = "12345"

NOW = int(time())
INDY_PROOF_REQ = {
    "name": PROOF_REQ_NAME,
    "version": PROOF_REQ_VERSION,
    "nonce": PROOF_REQ_NONCE,
    "requested_attributes": {
        "0_player_uuid": {
            "name": "player",
            "restrictions": [{"cred_def_id": CD_ID}],
            "non_revoked": {"from": NOW, "to": NOW},
        },
        "1_screencapture_uuid": {
            "name": "screenCapture",
            "restrictions": [{"cred_def_id": CD_ID}],
            "non_revoked": {"from": NOW, "to": NOW},
        },
    },
    "requested_predicates": {
        "0_highscore_GE_uuid": {
            "name": "highScore",
            "p_type": ">=",
            "p_value": 1000000,
            "restrictions": [{"cred_def_id": CD_ID}],
            "non_revoked": {"from": NOW, "to": NOW},
        }
    },
}


class TestPresentProofRoutes(AsyncTestCase):
    def setUp(self):
        self.context = AdminRequestContext.test_context()
        self.profile = self.context.profile
        injector = self.profile.context.injector

        Ledger = async_mock.MagicMock(BaseLedger, autospec=True)
        self.ledger = Ledger()
        self.ledger.get_schema = async_mock.CoroutineMock(
            return_value=async_mock.MagicMock()
        )
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value={"value": {"revocation": {"...": "..."}}}
        )
        self.ledger.get_revoc_reg_def = async_mock.CoroutineMock(
            return_value={
                "ver": "1.0",
                "id": RR_ID,
                "revocDefType": "CL_ACCUM",
                "tag": RR_ID.split(":")[-1],
                "credDefId": CD_ID,
                "value": {
                    "IssuanceType": "ISSUANCE_BY_DEFAULT",
                    "maxCredNum": 1000,
                    "publicKeys": {"accumKey": {"z": "1 ..."}},
                    "tailsHash": "3MLjUFQz9x9n5u9rFu8Ba9C5bo4HNFjkPNc54jZPSNaZ",
                    "tailsLocation": "http://sample.ca/path",
                },
            }
        )
        self.ledger.get_revoc_reg_delta = async_mock.CoroutineMock(
            return_value=(
                {
                    "ver": "1.0",
                    "value": {"prevAccum": "1 ...", "accum": "21 ...", "issued": [1]},
                },
                NOW,
            )
        )
        self.ledger.get_revoc_reg_entry = async_mock.CoroutineMock(
            return_value=(
                {
                    "ver": "1.0",
                    "value": {"prevAccum": "1 ...", "accum": "21 ...", "issued": [1]},
                },
                NOW,
            )
        )
        injector.bind_instance(BaseLedger, self.ledger)

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

    async def test_validate(self):
        schema = test_module.V20PresProposalByFormatSchema()
        schema.validate_fields({"indy": {"attributes": [], "predicates": []}})
        schema.validate_fields({"dif": {"some_dif_criterion": "..."}})
        schema.validate_fields(
            {
                "indy": {"attributes": [], "predicates": []},
                "dif": {"some_dif_criterion": "..."},
            }
        )
        with self.assertRaises(test_module.ValidationError):
            schema.validate_fields({})
        with self.assertRaises(test_module.ValidationError):
            schema.validate_fields({"veres-one": {"no": "support"}})

        schema = test_module.V20PresRequestByFormatSchema()
        schema.validate_fields({"indy": {"...": "..."}})
        schema.validate_fields({"dif": {"...": "..."}})
        schema.validate_fields({"indy": {"...": "..."}, "dif": {"...": "..."}})
        with self.assertRaises(test_module.ValidationError):
            schema.validate_fields({})
        with self.assertRaises(test_module.ValidationError):
            schema.validate_fields({"veres-one": {"no": "support"}})

        schema = test_module.V20PresSpecByFormatRequestSchema()
        schema.validate_fields({"indy": {"...": "..."}})
        schema.validate_fields({"dif": {"...": "..."}})
        with self.assertRaises(test_module.ValidationError):
            schema.validate_fields({"indy": {"...": "..."}, "dif": {"...": "..."}})
        with self.assertRaises(test_module.ValidationError):
            schema.validate_fields({})
        with self.assertRaises(test_module.ValidationError):
            schema.validate_fields({"veres-one": {"no": "support"}})

    async def test_validate_proof_req_attr_spec(self):
        aspec = IndyProofReqAttrSpecSchema()
        aspec.validate_fields({"name": "attr0"})
        aspec.validate_fields(
            {
                "names": ["attr0", "attr1"],
                "restrictions": [{"attr::attr1::value": "my-value"}],
            }
        )
        aspec.validate_fields(
            {"name": "attr0", "restrictions": [{"schema_name": "preferences"}]}
        )
        with self.assertRaises(ValidationError):
            aspec.validate_fields({})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"name": "attr0", "names": ["attr1", "attr2"]})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"names": ["attr1", "attr2"]})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"names": ["attr0", "attr1"], "restrictions": []})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"names": ["attr0", "attr1"], "restrictions": [{}]})

    async def test_present_proof_list(self):
        self.request.query = {
            "thread_id": "thread_id_0",
            "connection_id": "conn_id_0",
            "role": "dummy",
            "state": "dummy",
        }

        mock_pres_ex_rec_inst = async_mock.MagicMock(
            serialize=async_mock.MagicMock(
                return_value={"thread_id": "sample-thread-id"}
            )
        )
        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_pres_ex_rec_cls.query = async_mock.CoroutineMock(
                return_value=[mock_pres_ex_rec_inst]
            )

            await test_module.present_proof_list(self.request)
            mock_response.assert_called_once_with(
                {"results": [mock_pres_ex_rec_inst.serialize.return_value]}
            )

    async def test_present_proof_list_x(self):
        self.request.query = {
            "thread_id": "thread_id_0",
            "connection_id": "conn_id_0",
            "role": "dummy",
            "state": "dummy",
        }

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls:
            mock_pres_ex_rec_cls.query = async_mock.CoroutineMock(
                side_effect=test_module.StorageError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_list(self.request)

    async def test_present_proof_credentials_list_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls:
            mock_pres_ex_rec_cls.retrieve_by_id = async_mock.CoroutineMock()

            # Emulate storage not found (bad presentation exchange id)
            mock_pres_ex_rec_cls.retrieve_by_id.side_effect = StorageNotFoundError()

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.present_proof_credentials_list(self.request)

    async def test_present_proof_credentials_x(self):
        self.request.match_info = {
            "pres_ex_id": "123-456-789",
            "referent": "myReferent1",
        }
        self.request.query = {"extra_query": {}}
        returned_credentials = [{"name": "Credential1"}, {"name": "Credential2"}]
        self.profile.context.injector.bind_instance(
            IndyHolder,
            async_mock.MagicMock(
                get_credentials_for_presentation_request_by_referent=(
                    async_mock.CoroutineMock(side_effect=test_module.IndyHolderError())
                )
            ),
        )

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls:
            mock_pres_ex_rec_cls.return_value = async_mock.MagicMock(
                retrieve_by_id=async_mock.CoroutineMock()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_credentials_list(self.request)

    async def test_present_proof_credentials_list_single_referent(self):
        self.request.match_info = {
            "pres_ex_id": "123-456-789",
            "referent": "myReferent1",
        }
        self.request.query = {"extra_query": {}}

        returned_credentials = [{"name": "Credential1"}, {"name": "Credential2"}]
        self.profile.context.injector.bind_instance(
            IndyHolder,
            async_mock.MagicMock(
                get_credentials_for_presentation_request_by_referent=(
                    async_mock.CoroutineMock(return_value=returned_credentials)
                )
            ),
        )

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_pres_ex_rec_cls.return_value = async_mock.MagicMock(
                retrieve_by_id=async_mock.CoroutineMock()
            )

            await test_module.present_proof_credentials_list(self.request)
            mock_response.assert_called_once_with(returned_credentials)

    async def test_present_proof_credentials_list_multiple_referents(self):
        self.request.match_info = {
            "pres_ex_id": "123-456-789",
            "referent": "myReferent1,myReferent2",
        }
        self.request.query = {"extra_query": {}}

        returned_credentials = [{"name": "Credential1"}, {"name": "Credential2"}]
        self.profile.context.injector.bind_instance(
            IndyHolder,
            async_mock.MagicMock(
                get_credentials_for_presentation_request_by_referent=(
                    async_mock.CoroutineMock(return_value=returned_credentials)
                )
            ),
        )

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_pres_ex_rec_cls.return_value = async_mock.MagicMock(
                retrieve_by_id=async_mock.CoroutineMock()
            )

            await test_module.present_proof_credentials_list(self.request)
            mock_response.assert_called_once_with(returned_credentials)

    async def test_present_proof_retrieve(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_pres_ex_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    serialize=async_mock.MagicMock(
                        return_value={"thread_id": "sample-thread-id"}
                    )
                )
            )

            await test_module.present_proof_retrieve(self.request)
            mock_response.assert_called_once_with({"thread_id": "sample-thread-id"})

    async def test_present_proof_retrieve_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls:
            mock_pres_ex_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.present_proof_retrieve(self.request)

    async def test_present_proof_retrieve_ser_x(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        mock_pres_ex_rec_inst = async_mock.MagicMock(
            connection_id="abc123",
            thread_id="thid123",
            serialize=async_mock.MagicMock(side_effect=test_module.BaseModelError()),
        )
        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls:
            mock_pres_ex_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_pres_ex_rec_inst
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_retrieve(self.request)

    async def test_present_proof_send_proposal(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "connection_id": "dummy-conn-id",
                "presentation_proposal": {
                    V20PresFormat.Format.INDY.api: INDY_PROOF_REQ
                },
            }
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_conn_rec.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(is_ready=True)
            )
            mock_px_rec_inst = async_mock.MagicMock()
            mock_pres_mgr.return_value.create_exchange_for_proposal = (
                async_mock.CoroutineMock(return_value=mock_px_rec_inst)
            )

            await test_module.present_proof_send_proposal(self.request)
            mock_response.assert_called_once_with(
                mock_px_rec_inst.serialize.return_value
            )

    async def test_present_proof_send_proposal_no_conn_record(self):
        self.request.json = async_mock.CoroutineMock()

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec:
            mock_conn_rec.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_proposal(self.request)

    async def test_present_proof_send_proposal_not_ready(self):
        self.request.json = async_mock.CoroutineMock()

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresProposal", autospec=True
        ) as mock_proposal:
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(is_ready=False)
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.present_proof_send_proposal(self.request)

    async def test_present_proof_send_proposal_x(self):
        self.request.json = async_mock.CoroutineMock()

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr:
            mock_pres_mgr.return_value.create_exchange_for_proposal = (
                async_mock.CoroutineMock(side_effect=test_module.StorageError())
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_proposal(self.request)

    async def test_present_proof_create_request(self):
        indy_proof_req = deepcopy(INDY_PROOF_REQ)
        indy_proof_req.pop("nonce")  # exercise _add_nonce()

        self.request.json = async_mock.CoroutineMock(
            return_value={
                "comment": "dummy",
                "presentation_request": {V20PresFormat.Format.INDY.api: indy_proof_req},
            }
        )

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresRequest", autospec=True
        ) as mock_pres_request, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_px_rec_inst = async_mock.MagicMock(
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                )
            )
            mock_pres_mgr_inst = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    return_value=mock_px_rec_inst
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            await test_module.present_proof_create_request(self.request)
            mock_response.assert_called_once_with(
                mock_px_rec_inst.serialize.return_value
            )

    async def test_present_proof_create_request_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "comment": "dummy",
                "presentation_request": {V20PresFormat.Format.INDY.api: INDY_PROOF_REQ},
            }
        )

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresRequest", autospec=True
        ) as mock_pres_request, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_px_rec_inst = async_mock.MagicMock()
            mock_pres_mgr_inst = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_create_request(self.request)

    async def test_present_proof_send_free_request(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "connection_id": "dummy",
                "comment": "dummy",
                "presentation_request": {V20PresFormat.Format.INDY.api: INDY_PROOF_REQ},
            }
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresRequest", autospec=True
        ) as mock_pres_request, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock()
            mock_px_rec_inst = async_mock.MagicMock(
                serialize=async_mock.MagicMock({"thread_id": "sample-thread-id"})
            )

            mock_pres_mgr_inst = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    return_value=mock_px_rec_inst
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            await test_module.present_proof_send_free_request(self.request)
            mock_response.assert_called_once_with(
                mock_px_rec_inst.serialize.return_value
            )

    async def test_present_proof_send_free_request_not_found(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"connection_id": "dummy"}
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", async_mock.MagicMock()
        ) as mock_conn_rec_cls:
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_free_request(self.request)

    async def test_present_proof_send_free_request_not_ready(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"connection_id": "dummy", "proof_request": {}}
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", async_mock.MagicMock()
        ) as mock_conn_rec_cls:
            mock_conn_rec_inst = async_mock.MagicMock(is_ready=False)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.present_proof_send_free_request(self.request)

    async def test_present_proof_send_free_request_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "connection_id": "dummy",
                "comment": "dummy",
                "presentation_request": {V20PresFormat.Format.INDY.api: INDY_PROOF_REQ},
            }
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresRequest", autospec=True
        ) as mock_pres_request, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_conn_rec_inst = async_mock.MagicMock()
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )
            mock_px_rec_inst = async_mock.MagicMock(
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                )
            )
            mock_pres_mgr_inst = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_free_request(self.request)

    async def test_present_proof_send_bound_request(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseLedger,
            async_mock.MagicMock(
                __aenter__=async_mock.CoroutineMock(),
                __aexit__=async_mock.CoroutineMock(),
            ),
        )
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PROPOSAL_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )
            mock_conn_rec_inst = async_mock.MagicMock(
                is_ready=True,
            )
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )
            mock_pres_request = async_mock.MagicMock()

            mock_pres_mgr_inst = async_mock.MagicMock(
                create_bound_request=async_mock.CoroutineMock(
                    return_value=(mock_px_rec_inst, mock_pres_request)
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            await test_module.present_proof_send_bound_request(self.request)
            mock_response.assert_called_once_with(
                mock_px_rec_inst.serialize.return_value
            )

    async def test_present_proof_send_bound_request_not_found(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseLedger,
            async_mock.MagicMock(
                __aenter__=async_mock.CoroutineMock(),
                __aexit__=async_mock.CoroutineMock(),
            ),
        )
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PROPOSAL_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_bound_request(self.request)

    async def test_present_proof_send_bound_request_not_ready(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseLedger,
            async_mock.MagicMock(
                __aenter__=async_mock.CoroutineMock(),
                __aexit__=async_mock.CoroutineMock(),
            ),
        )
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PROPOSAL_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )
            mock_conn_rec_inst = async_mock.MagicMock(
                is_ready=False,
            )
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.present_proof_send_bound_request(self.request)

    async def test_present_proof_send_bound_request_px_rec_not_found(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError("no such record")
            )
            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.present_proof_send_bound_request(self.request)
            assert "no such record" in str(context.exception)

    async def test_present_proof_send_bound_request_bad_state(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseLedger,
            async_mock.MagicMock(
                __aenter__=async_mock.CoroutineMock(),
                __aexit__=async_mock.CoroutineMock(),
            ),
        )
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_DONE,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_bound_request(self.request)

    async def test_present_proof_send_bound_request_x(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        self.profile.context.injector.bind_instance(
            BaseLedger,
            async_mock.MagicMock(
                __aenter__=async_mock.CoroutineMock(),
                __aexit__=async_mock.CoroutineMock(),
            ),
        )
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PROPOSAL_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )
            mock_conn_rec_inst = async_mock.MagicMock(
                is_ready=True,
            )
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            mock_pres_mgr_inst = async_mock.MagicMock(
                create_bound_request=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_bound_request(self.request)

    async def test_present_proof_send_presentation(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "indy": {
                    "comment": "dummy",
                    "self_attested_attributes": {},
                    "requested_attributes": {},
                    "requested_predicates": {},
                }
            }
        )
        self.request.match_info = {
            "pres_ex_id": "dummy",
        }
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_REQUEST_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            mock_conn_rec_inst = async_mock.MagicMock(is_ready=True)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            mock_pres_mgr_inst = async_mock.MagicMock(
                create_pres=async_mock.CoroutineMock(
                    return_value=(mock_px_rec_inst, async_mock.MagicMock())
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            await test_module.present_proof_send_presentation(self.request)
            mock_response.assert_called_once_with(
                mock_px_rec_inst.serialize.return_value
            )

    async def test_present_proof_send_presentation_px_rec_not_found(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "indy": {
                    "comment": "dummy",
                    "self_attested_attributes": {},
                    "requested_attributes": {},
                    "requested_predicates": {},
                }
            }
        )
        self.request.match_info = {
            "pres_ex_id": "dummy",
        }

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError("no such record")
            )

            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.present_proof_send_presentation(self.request)
            assert "no such record" in str(context.exception)

    async def test_present_proof_send_presentation_not_found(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "indy": {
                    "comment": "dummy",
                    "self_attested_attributes": {},
                    "requested_attributes": {},
                    "requested_predicates": {},
                }
            }
        )
        self.request.match_info = {
            "pres_ex_id": "dummy",
        }
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_REQUEST_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            mock_conn_rec_inst = async_mock.MagicMock(is_ready=True)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_presentation(self.request)

    async def test_present_proof_send_presentation_not_ready(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "indy": {
                    "comment": "dummy",
                    "self_attested_attributes": {},
                    "requested_attributes": {},
                    "requested_predicates": {},
                }
            }
        )
        self.request.match_info = {
            "pres_ex_id": "dummy",
        }
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_REQUEST_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            mock_conn_rec_inst = async_mock.MagicMock(is_ready=True)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(is_ready=False)
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.present_proof_send_presentation(self.request)

    async def test_present_proof_send_presentation_bad_state(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "indy": {
                    "comment": "dummy",
                    "self_attested_attributes": {},
                    "requested_attributes": {},
                    "requested_predicates": {},
                }
            }
        )
        self.request.match_info = {
            "pres_ex_id": "dummy",
        }

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_DONE,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_presentation(self.request)

    async def test_present_proof_send_presentation_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "indy": {
                    "comment": "dummy",
                    "self_attested_attributes": {},
                    "requested_attributes": {},
                    "requested_predicates": {},
                }
            }
        )
        self.request.match_info = {
            "pres_ex_id": "dummy",
        }
        self.profile.context.injector.bind_instance(
            IndyVerifier,
            async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(),
            ),
        )

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_REQUEST_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            mock_conn_rec_inst = async_mock.MagicMock(is_ready=True)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            mock_pres_mgr_inst = async_mock.MagicMock(
                create_pres=async_mock.CoroutineMock(
                    side_effect=test_module.LedgerError()
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_send_presentation(self.request)

    async def test_present_proof_verify_presentation(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PRESENTATION_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )
            mock_conn_rec_inst = async_mock.MagicMock(is_ready=True)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            mock_pres_mgr_inst = async_mock.MagicMock(
                verify_pres=async_mock.CoroutineMock(return_value=mock_px_rec_inst)
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            await test_module.present_proof_verify_presentation(self.request)
            mock_response.assert_called_once_with({"thread_id": "sample-thread-id"})

    async def test_present_proof_verify_presentation_px_rec_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError("no such record")
            )

            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.present_proof_verify_presentation(self.request)
            assert "no such record" in str(context.exception)

    async def test_present_proof_verify_presentation_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PRESENTATION_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            mock_conn_rec_inst = async_mock.MagicMock(is_ready=True)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_verify_presentation(self.request)

    async def test_present_proof_verify_presentation_not_ready(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PRESENTATION_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )
            mock_conn_rec_inst = async_mock.MagicMock(is_ready=False)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.present_proof_verify_presentation(self.request)

    async def test_present_proof_verify_presentation_bad_state(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_DONE,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_verify_presentation(self.request)

    async def test_present_proof_verify_presentation_x(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "ConnRecord", autospec=True
        ) as mock_conn_rec_cls, async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec_cls, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_px_rec_inst = async_mock.MagicMock(
                connection_id="dummy",
                state=test_module.V20PresExRecord.STATE_PRESENTATION_RECEIVED,
                serialize=async_mock.MagicMock(
                    return_value={"thread_id": "sample-thread-id"}
                ),
            )
            mock_px_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_px_rec_inst
            )
            mock_conn_rec_inst = async_mock.MagicMock(is_ready=True)
            mock_conn_rec_cls.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_conn_rec_inst
            )

            mock_pres_mgr_inst = async_mock.MagicMock(
                verify_pres=async_mock.CoroutineMock(
                    side_effect=test_module.LedgerError()
                )
            )
            mock_pres_mgr_cls.return_value = mock_pres_mgr_inst

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_verify_presentation(self.request)

    async def test_present_proof_problem_report(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"description": "Did I say no problem? I meant 'No! Problem.'"}
        )
        self.request.match_info = {"pres_ex_id": "dummy"}
        magic_report = async_mock.MagicMock()

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:
            mock_pres_mgr_cls.return_value = async_mock.MagicMock(
                create_problem_report=async_mock.CoroutineMock(
                    return_value=magic_report
                )
            )
            mock_px_rec.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(connection_id="dummy-conn-id")
            )

            await test_module.present_proof_problem_report(self.request)

            self.request["outbound_message_router"].assert_awaited_once_with(
                magic_report,
                connection_id=mock_px_rec.retrieve_by_id.return_value.connection_id,
            )
            mock_response.assert_called_once_with({})

    async def test_present_proof_problem_report_bad_pres_ex_id(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"description": "Did I say no problem? I meant 'No! Problem.'"}
        )
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec:
            mock_px_rec.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=test_module.StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.present_proof_problem_report(self.request)

    async def test_present_proof_problem_report_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"description": "Did I say no problem? I meant 'No! Problem.'"}
        )
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec:
            mock_pres_mgr_cls.return_value = async_mock.MagicMock(
                create_problem_report=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError("Disk full")
                )
            )
            mock_px_rec.retrieve_by_id = async_mock.CoroutineMock()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_problem_report(self.request)

    async def test_present_proof_remove(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec, async_mock.patch.object(
            test_module.web, "json_response", async_mock.MagicMock()
        ) as mock_response:
            mock_px_rec.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=test_module.V20PresExRecord.STATE_DONE,
                    connection_id="dummy",
                    delete_record=async_mock.CoroutineMock(),
                )
            )

            await test_module.present_proof_remove(self.request)
            mock_response.assert_called_once_with({})

    async def test_present_proof_remove_px_rec_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec:
            mock_px_rec.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.present_proof_remove(self.request)

    async def test_present_proof_remove_x(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_px_rec:
            mock_px_rec.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=test_module.V20PresExRecord.STATE_DONE,
                    connection_id="dummy",
                    delete_record=async_mock.CoroutineMock(
                        side_effect=test_module.StorageError()
                    ),
                )
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.present_proof_remove(self.request)

    async def test_register(self):
        mock_app = async_mock.MagicMock()
        mock_app.add_routes = async_mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called_once()

    async def test_post_process_routes(self):
        mock_app = async_mock.MagicMock(_state={"swagger_dict": {}})
        test_module.post_process_routes(mock_app)
        assert "tags" in mock_app._state["swagger_dict"]
