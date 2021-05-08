import importlib

from asynctest import mock as async_mock, TestCase as AsyncTestCase

from marshmallow import ValidationError

from .....admin.request_context import AdminRequestContext
from .....indy.holder import IndyHolder
from .....indy.sdk.models.proof_request import IndyProofReqAttrSpecSchema
from .....indy.verifier import IndyVerifier
from .....ledger.base import BaseLedger
from .....storage.error import StorageNotFoundError

from .. import routes as test_module


class TestProofRoutes(AsyncTestCase):
    def setUp(self):
        self.context = AdminRequestContext.test_context()
        self.profile = self.context.profile
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

    async def test_presentation_exchange_list(self):
        self.request.query = {
            "thread_id": "thread_id_0",
            "connection_id": "conn_id_0",
            "role": "dummy",
            "state": "dummy",
        }

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.query = async_mock.CoroutineMock()
            mock_presentation_exchange.query.return_value = [mock_presentation_exchange]
            mock_presentation_exchange.serialize = async_mock.MagicMock()
            mock_presentation_exchange.serialize.return_value = {
                "thread_id": "sample-thread-id"
            }

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_list(self.request)
                mock_response.assert_called_once_with(
                    {"results": [mock_presentation_exchange.serialize.return_value]}
                )

    async def test_presentation_exchange_list_x(self):
        self.request.query = {
            "thread_id": "thread_id_0",
            "connection_id": "conn_id_0",
            "role": "dummy",
            "state": "dummy",
        }

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.query = async_mock.CoroutineMock(
                side_effect=test_module.StorageError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_list(self.request)

    async def test_presentation_exchange_credentials_list_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock()

            # Emulate storage not found (bad presentation exchange id)
            mock_presentation_exchange.retrieve_by_id.side_effect = StorageNotFoundError

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_credentials_list(self.request)

    async def test_presentation_exchange_credentials_x(self):
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

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.return_value.retrieve_by_id.return_value = (
                mock_presentation_exchange
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_credentials_list(self.request)

    async def test_presentation_exchange_credentials_list_single_referent(self):
        self.request.match_info = {
            "pres_ex_id": "123-456-789",
            "referent": "myReferent1",
        }
        self.request.query = {"extra_query": {}}

        returned_credentials = [{"name": "Credential1"}, {"name": "Credential2"}]
        self.profile.context.injector.bind_instance(
            IndyHolder,
            async_mock.MagicMock(
                get_credentials_for_presentation_request_by_referent=async_mock.CoroutineMock(
                    return_value=returned_credentials
                )
            ),
        )

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.return_value.retrieve_by_id.return_value = (
                mock_presentation_exchange
            )

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_credentials_list(self.request)
                mock_response.assert_called_once_with(returned_credentials)

    async def test_presentation_exchange_credentials_list_multiple_referents(self):
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

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.return_value.retrieve_by_id.return_value = (
                mock_presentation_exchange
            )

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_credentials_list(self.request)
                mock_response.assert_called_once_with(returned_credentials)

    async def test_presentation_exchange_retrieve(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_pres_ex:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_pres_ex.retrieve_by_id = async_mock.CoroutineMock()
            mock_pres_ex.retrieve_by_id.return_value = mock_pres_ex
            mock_pres_ex.serialize = async_mock.MagicMock()
            mock_pres_ex.serialize.return_value = {"thread_id": "sample-thread-id"}

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_retrieve(self.request)
                mock_response.assert_called_once_with(
                    mock_pres_ex.serialize.return_value
                )

    async def test_presentation_exchange_retrieve_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_pres_ex:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_pres_ex.retrieve_by_id = async_mock.CoroutineMock()

            # Emulate storage not found (bad presentation exchange id)
            mock_pres_ex.retrieve_by_id.side_effect = StorageNotFoundError

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_retrieve(self.request)

    async def test_presentation_exchange_retrieve_ser_x(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        mock_pres_ex_rec = async_mock.MagicMock(
            connection_id="abc123", thread_id="thid123"
        )
        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_pres_ex:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_pres_ex.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_pres_ex_rec
            )
            mock_pres_ex_rec.serialize = async_mock.MagicMock(
                side_effect=test_module.BaseModelError()
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_retrieve(self.request)

    async def test_presentation_exchange_send_proposal(self):
        self.request.json = async_mock.CoroutineMock()

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.sdk.models.pres_preview.IndyPresPreview",
            autospec=True,
        ) as mock_preview:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange_record = async_mock.MagicMock()
            mock_presentation_manager.return_value.create_exchange_for_proposal = (
                async_mock.CoroutineMock(return_value=mock_presentation_exchange_record)
            )

            mock_preview.return_value.deserialize.return_value = async_mock.MagicMock()

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_send_proposal(self.request)
                mock_response.assert_called_once_with(
                    mock_presentation_exchange_record.serialize.return_value
                )

    async def test_presentation_exchange_send_proposal_no_conn_record(self):
        self.request.json = async_mock.CoroutineMock()

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record:

            # Since we are mocking import
            importlib.reload(test_module)

            # Emulate storage not found (bad connection id)
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_proposal(self.request)

    async def test_presentation_exchange_send_proposal_not_ready(self):
        self.request.json = async_mock.CoroutineMock()

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.indy.sdk.models.pres_preview.IndyPresPreview",
            autospec=True,
        ) as mock_preview, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "messages.presentation_proposal.PresentationProposal"
            ),
            autospec=True,
        ) as mock_proposal:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock()
            mock_connection_record.retrieve_by_id.return_value.is_ready = False

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.presentation_exchange_send_proposal(self.request)

    async def test_presentation_exchange_send_proposal_x(self):
        self.request.json = async_mock.CoroutineMock()

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.sdk.models.pres_preview.IndyPresPreview",
            autospec=True,
        ) as mock_preview:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange_record = async_mock.MagicMock()
            mock_presentation_manager.return_value.create_exchange_for_proposal = (
                async_mock.CoroutineMock(side_effect=test_module.StorageError())
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_proposal(self.request)

    async def test_presentation_exchange_create_request(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"comment": "dummy", "proof_request": {}}
        )

        with async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.sdk.models.pres_preview.IndyPresPreview",
            autospec=True,
        ) as mock_preview, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_generate_nonce = async_mock.CoroutineMock()

            mock_attach_decorator.data_base64 = async_mock.MagicMock(
                return_value=mock_attach_decorator
            )
            mock_presentation_exchange.serialize = async_mock.MagicMock()
            mock_presentation_exchange.serialize.return_value = {
                "thread_id": "sample-thread-id"
            }
            mock_mgr = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    return_value=mock_presentation_exchange
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_create_request(self.request)
                mock_response.assert_called_once_with(
                    mock_presentation_exchange.serialize.return_value
                )

    async def test_presentation_exchange_create_request_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"comment": "dummy", "proof_request": {}}
        )

        with async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.sdk.models.pres_preview.IndyPresPreview",
            autospec=True,
        ) as mock_preview, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.serialize = async_mock.MagicMock()
            mock_presentation_exchange.serialize.return_value = {
                "thread_id": "sample-thread-id"
            }
            mock_mgr = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_create_request(self.request)

    async def test_presentation_exchange_send_free_request(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "connection_id": "dummy",
                "comment": "dummy",
                "proof_request": {},
            }
        )

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch(
            "aries_cloudagent.indy.sdk.models.pres_preview.IndyPresPreview",
            autospec=True,
        ) as mock_preview, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )
            mock_attach_decorator.data_base64 = async_mock.MagicMock(
                return_value=mock_attach_decorator
            )
            mock_presentation_exchange.serialize = async_mock.MagicMock()
            mock_presentation_exchange.serialize.return_value = {
                "thread_id": "sample-thread-id"
            }

            mock_mgr = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    return_value=mock_presentation_exchange
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_send_free_request(self.request)
                mock_response.assert_called_once_with(
                    mock_presentation_exchange.serialize.return_value
                )

    async def test_presentation_exchange_send_free_request_not_found(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"connection_id": "dummy"}
        )

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock()
            mock_connection_record.retrieve_by_id.side_effect = StorageNotFoundError

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_free_request(self.request)

    async def test_presentation_exchange_send_free_request_not_ready(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"connection_id": "dummy", "proof_request": {}}
        )

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_connection_record.is_ready = False
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.presentation_exchange_send_free_request(self.request)

    async def test_presentation_exchange_send_free_request_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "connection_id": "dummy",
                "comment": "dummy",
                "proof_request": {},
            }
        )

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_generate_nonce = async_mock.CoroutineMock()

            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )
            mock_attach_decorator.data_base64 = async_mock.MagicMock(
                return_value=mock_attach_decorator
            )
            mock_presentation_exchange.serialize = async_mock.MagicMock()
            mock_presentation_exchange.serialize.return_value = {
                "thread_id": "sample-thread-id"
            }

            mock_mgr = async_mock.MagicMock(
                create_exchange_for_request=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_free_request(self.request)

    async def test_presentation_exchange_send_bound_request(self):
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

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0."
            "models.presentation_exchange.V10PresentationExchange",
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.connection_id = "dummy"
            mock_presentation_exchange.state = (
                test_module.V10PresentationExchange.STATE_PROPOSAL_RECEIVED
            )
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_presentation_exchange
            )
            mock_presentation_exchange.serialize = async_mock.MagicMock()
            mock_presentation_exchange.serialize.return_value = {
                "thread_id": "sample-thread-id"
            }
            mock_connection_record.is_ready = True
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )

            mock_mgr = async_mock.MagicMock(
                create_bound_request=async_mock.CoroutineMock(
                    return_value=(mock_presentation_exchange, mock_presentation_request)
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_send_bound_request(self.request)
                mock_response.assert_called_once_with(
                    mock_presentation_exchange.serialize.return_value
                )

    async def test_presentation_exchange_send_bound_request_not_found(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.connection_id = "dummy"
            mock_presentation_exchange.state = (
                test_module.V10PresentationExchange.STATE_PROPOSAL_RECEIVED
            )
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_presentation_exchange
            )

            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock()
            mock_connection_record.retrieve_by_id.side_effect = StorageNotFoundError

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_bound_request(self.request)

    async def test_presentation_exchange_send_bound_request_not_ready(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.connection_id = "dummy"
            mock_presentation_exchange.state = (
                test_module.V10PresentationExchange.STATE_PROPOSAL_RECEIVED
            )
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_presentation_exchange
            )

            mock_connection_record.is_ready = False
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.presentation_exchange_send_bound_request(self.request)

    async def test_presentation_exchange_send_bound_request_px_rec_not_found(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module.V10PresentationExchange,
            "retrieve_by_id",
            async_mock.CoroutineMock(),
        ) as mock_retrieve:
            mock_retrieve.side_effect = StorageNotFoundError("no such record")
            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.presentation_exchange_send_bound_request(self.request)
            assert "no such record" in str(context.exception)

    async def test_presentation_exchange_send_bound_request_bad_state(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.connection_id = "dummy"
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_PRESENTATION_ACKED
                )
            )
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_bound_request(self.request)

    async def test_presentation_exchange_send_bound_request_x(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.connection_id = "dummy"
            mock_presentation_exchange.state = (
                test_module.V10PresentationExchange.STATE_PROPOSAL_RECEIVED
            )
            mock_presentation_exchange.connection_id = "abc123"
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_presentation_exchange
            )
            mock_presentation_exchange.serialize = async_mock.MagicMock()
            mock_presentation_exchange.serialize.return_value = {
                "thread_id": "sample-thread-id",
            }
            mock_connection_record.is_ready = True
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )

            mock_mgr = async_mock.MagicMock(
                create_bound_request=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError()
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_bound_request(self.request)

    async def test_presentation_exchange_send_presentation(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "comment": "dummy",
                "self_attested_attributes": {},
                "requested_attributes": {},
                "requested_predicates": {},
            }
        )
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

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.state = (
                test_module.V10PresentationExchange.STATE_REQUEST_RECEIVED
            )
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_REQUEST_RECEIVED,
                    connection_id="dummy",
                    serialize=async_mock.MagicMock(
                        return_value={"thread_id": "sample-thread-id"}
                    ),
                )
            )
            mock_connection_record.is_ready = True
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )
            mock_mgr = async_mock.MagicMock(
                create_presentation=async_mock.CoroutineMock(
                    return_value=(mock_presentation_exchange, async_mock.MagicMock())
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_send_presentation(self.request)
                mock_response.assert_called_once_with(
                    mock_presentation_exchange.serialize.return_value
                )

    async def test_presentation_exchange_send_presentation_px_rec_not_found(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module.V10PresentationExchange,
            "retrieve_by_id",
            async_mock.CoroutineMock(),
        ) as mock_retrieve:
            mock_retrieve.side_effect = StorageNotFoundError("no such record")
            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.presentation_exchange_send_presentation(self.request)
            assert "no such record" in str(context.exception)

    async def test_presentation_exchange_send_presentation_not_found(self):
        self.request.json = async_mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_REQUEST_RECEIVED,
                    connection_id="dummy",
                )
            )

            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_presentation(self.request)

    async def test_presentation_exchange_send_presentation_not_ready(self):
        self.request.json = async_mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_REQUEST_RECEIVED,
                    connection_id="dummy",
                )
            )

            mock_connection_record.is_ready = False
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.presentation_exchange_send_presentation(self.request)

    async def test_presentation_exchange_send_presentation_bad_state(self):
        self.request.json = async_mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_PRESENTATION_ACKED
                )
            )
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_presentation(self.request)

    async def test_presentation_exchange_send_presentation_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={
                "comment": "dummy",
                "self_attested_attributes": {},
                "requested_attributes": {},
                "requested_predicates": {},
            }
        )
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch.object(
            test_module, "IndyPresPreview", autospec=True
        ) as mock_presentation_proposal, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.state = (
                test_module.V10PresentationExchange.STATE_REQUEST_RECEIVED
            )
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_REQUEST_RECEIVED,
                    connection_id="dummy",
                    serialize=async_mock.MagicMock(
                        return_value={"thread_id": "sample-thread-id"}
                    ),
                )
            )
            mock_connection_record.is_ready = True
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )
            mock_mgr = async_mock.MagicMock(
                create_presentation=async_mock.CoroutineMock(
                    side_effect=test_module.LedgerError()
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_presentation(self.request)

    async def test_presentation_exchange_verify_presentation(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            "aries_cloudagent.indy.util.generate_pr_nonce",
            autospec=True,
        ) as mock_generate_nonce, async_mock.patch(
            "aries_cloudagent.indy.sdk.models.pres_preview.IndyPresPreview",
            autospec=True,
        ) as mock_preview, async_mock.patch.object(
            test_module, "PresentationRequest", autospec=True
        ) as mock_presentation_request, async_mock.patch(
            "aries_cloudagent.messaging.decorators.attach_decorator.AttachDecorator",
            autospec=True,
        ) as mock_attach_decorator, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_PRESENTATION_RECEIVED,
                    connection_id="dummy",
                    thread_id="dummy",
                    serialize=async_mock.MagicMock(
                        return_value={"thread_id": "sample-thread-id"}
                    ),
                )
            )
            mock_connection_record.is_ready = True
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )
            mock_mgr = async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(
                    return_value=mock_presentation_exchange.retrieve_by_id.return_value
                )
            )
            mock_presentation_manager.return_value = mock_mgr

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_verify_presentation(
                    self.request
                )
                mock_response.assert_called_once_with({"thread_id": "sample-thread-id"})

    async def test_presentation_exchange_verify_presentation_px_rec_not_found(self):
        self.request.json = async_mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch.object(
            test_module.V10PresentationExchange,
            "retrieve_by_id",
            async_mock.CoroutineMock(),
        ) as mock_retrieve:
            mock_retrieve.side_effect = StorageNotFoundError("no such record")
            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.presentation_exchange_verify_presentation(
                    self.request
                )
            assert "no such record" in str(context.exception)

    async def test_presentation_exchange_verify_presentation_not_found(self):
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

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_PRESENTATION_RECEIVED,
                    connection_id="dummy",
                )
            )

            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_verify_presentation(
                    self.request
                )

    async def test_presentation_exchange_verify_presentation_not_ready(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_PRESENTATION_RECEIVED,
                    connection_id="dummy",
                )
            )

            mock_connection_record.is_ready = False
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.presentation_exchange_verify_presentation(
                    self.request
                )

    async def test_presentation_exchange_verify_presentation_bad_state(self):
        self.request.json = async_mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_PRESENTATION_ACKED
                )
            )
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_verify_presentation(
                    self.request
                )

    async def test_presentation_exchange_verify_presentation_x(self):
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

        with async_mock.patch(
            "aries_cloudagent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_presentation_manager, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_PRESENTATION_RECEIVED,
                    connection_id="dummy",
                    thread_id="dummy",
                    serialize=async_mock.MagicMock(
                        return_value={"thread_id": "sample-thread-id"}
                    ),
                )
            )

            mock_connection_record.is_ready = True
            mock_connection_record.retrieve_by_id = async_mock.CoroutineMock(
                return_value=mock_connection_record
            )
            mock_mgr = async_mock.MagicMock(
                verify_presentation=async_mock.CoroutineMock(
                    side_effect=test_module.LedgerError()
                ),
            )
            mock_presentation_manager.return_value = mock_mgr

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_verify_presentation(
                    self.request
                )

    async def test_presentation_exchange_problem_report(self):
        self.request.json = async_mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}
        magic_report = async_mock.MagicMock()

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_pres_ex, async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_pres_mgr_cls, async_mock.patch.object(
            test_module.web, "json_response"
        ) as mock_response:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_pres_mgr_cls.return_value = async_mock.MagicMock(
                create_problem_report=async_mock.CoroutineMock(
                    return_value=magic_report
                )
            )
            mock_pres_ex.retrieve_by_id = async_mock.CoroutineMock()

            await test_module.presentation_exchange_problem_report(self.request)

            self.request["outbound_message_router"].assert_awaited_once_with(
                magic_report,
                connection_id=mock_pres_ex.retrieve_by_id.return_value.connection_id,
            )
            mock_response.assert_called_once_with({})

    async def test_presentation_exchange_problem_report_bad_pres_ex_id(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"description": "Did I say no problem? I meant 'no: problem.'"}
        )
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_pres_mgr_cls, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_pres_ex:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_pres_ex.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=test_module.StorageNotFoundError()
            )

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_problem_report(self.request)

    async def test_presentation_exchange_problem_report_x(self):
        self.request.json = async_mock.CoroutineMock(
            return_value={"description": "Did I say no problem? I meant 'no: problem.'"}
        )
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            "aries_cloudagent.protocols.present_proof.v1_0.manager.PresentationManager",
            autospec=True,
        ) as mock_pres_mgr_cls, async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_pres_ex:

            # Since we are mocking import
            importlib.reload(test_module)
            mock_pres_mgr_cls.return_value = async_mock.MagicMock(
                create_problem_report=async_mock.CoroutineMock(
                    side_effect=test_module.StorageError("Disk full")
                )
            )
            mock_pres_ex.retrieve_by_id = async_mock.CoroutineMock()

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_problem_report(self.request)

    async def test_presentation_exchange_remove(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_VERIFIED,
                    connection_id="dummy",
                    delete_record=async_mock.CoroutineMock(),
                )
            )

            with async_mock.patch.object(
                test_module.web, "json_response"
            ) as mock_response:
                await test_module.presentation_exchange_remove(self.request)
                mock_response.assert_called_once_with({})

    async def test_presentation_exchange_remove_not_found(self):
        self.request.json = async_mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            # Emulate storage not found (bad pres ex id)
            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError
            )

            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_remove(self.request)

    async def test_presentation_exchange_remove_x(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with async_mock.patch(
            (
                "aries_cloudagent.protocols.present_proof.v1_0."
                "models.presentation_exchange.V10PresentationExchange"
            ),
            autospec=True,
        ) as mock_presentation_exchange:

            # Since we are mocking import
            importlib.reload(test_module)

            mock_presentation_exchange.retrieve_by_id = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(
                    state=mock_presentation_exchange.STATE_VERIFIED,
                    connection_id="dummy",
                    delete_record=async_mock.CoroutineMock(
                        side_effect=test_module.StorageError()
                    ),
                )
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_remove(self.request)

    async def test_register(self):
        mock_app = async_mock.MagicMock()
        mock_app.add_routes = async_mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called_once()

    async def test_post_process_routes(self):
        mock_app = async_mock.MagicMock(_state={"swagger_dict": {}})
        test_module.post_process_routes(mock_app)
        assert "tags" in mock_app._state["swagger_dict"]
