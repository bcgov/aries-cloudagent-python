from asynctest import mock as async_mock, TestCase as AsyncTestCase

from ......indy.sdk.models.pres_preview import IndyPresAttrSpec, IndyPresPreview
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......storage.error import StorageNotFoundError
from ......transport.inbound.receipt import MessageReceipt

from .....didcomm_prefix import DIDCommPrefix

from ...messages.pres_format import V20PresFormat
from ...messages.pres_proposal import V20PresProposal
from ...messages.pres_request import V20PresRequest

from .. import pres_request_handler as test_module

S_ID = "NcYxiDXkpYi6ov5FcYDi1e:2:vidya:1.0"
CD_ID = f"NcYxiDXkpYi6ov5FcYDi1e:3:CL:{S_ID}:tag1"
INDY_PROOF_REQ = {
    "name": "proof-request",
    "version": "1.0",
    "nonce": "1234567890",
    "requested_attributes": {
        "0_favourite_uuid": {
            "name": "favourite",
            "restrictions": [
                {
                    "cred_def_id": CD_ID,
                }
            ],
        },
        "1_icon_uuid": {
            "name": "icon",
            "restrictions": [
                {
                    "cred_def_id": CD_ID,
                }
            ],
        },
    },
    "requested_predicates": {},
}
INDY_PROOF_REQ_PRED = {
    "name": "proof-request",
    "version": "1.0",
    "nonce": "1234567890",
    "requested_attributes": {},
    "requested_predicates": {
        "0_score_GE_uuid": {
            "name": "score",
            "p_type": ">=",
            "p_value": 1000000,
            "restrictions": [
                {
                    "cred_def_id": CD_ID,
                }
            ],
        }
    },
}


class TestPresRequestHandler(AsyncTestCase):
    async def test_called(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message_receipt = MessageReceipt()
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=async_mock.MagicMock()
        )

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec:

            mock_pres_ex_rec.retrieve_by_tag_filter = async_mock.CoroutineMock(
                return_value=mock_pres_ex_rec
            )

            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(auto_present=False)
            )

            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            mock_pres_ex_rec
        )
        assert not responder.messages

    async def test_called_not_found(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message_receipt = MessageReceipt()
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=async_mock.MagicMock()
        )

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec:

            mock_pres_ex_rec.retrieve_by_tag_filter = async_mock.CoroutineMock(
                side_effect=StorageNotFoundError
            )
            mock_pres_ex_rec.return_value = mock_pres_ex_rec

            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(auto_present=False)
            )

            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            mock_pres_ex_rec
        )
        assert not responder.messages

    async def test_called_auto_present(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=INDY_PROOF_REQ
        )
        request_context.message_receipt = MessageReceipt()
        pres_proposal = V20PresProposal(
            formats=[
                V20PresFormat(
                    attach_id="indy",
                    format_=V20PresFormat.Format.INDY.aries,
                )
            ],
            proposals_attach=[
                AttachDecorator.data_base64(INDY_PROOF_REQ, ident="indy")
            ],
        )

        px_rec_instance = test_module.V20PresExRecord(
            pres_proposal=pres_proposal.serialize(),
            auto_present=True,
        )
        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module, "IndyHolder", autospec=True
        ) as mock_holder:

            mock_holder.get_credentials_for_presentation_request_by_referent = (
                async_mock.CoroutineMock(
                    return_value=[{"cred_info": {"referent": "dummy"}}]
                )
            )
            request_context.inject = async_mock.MagicMock(return_value=mock_holder)

            mock_pres_ex_rec_cls.return_value = px_rec_instance
            mock_pres_ex_rec_cls.retrieve_by_tag_filter = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )
            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )

            mock_pres_mgr.return_value.create_pres = async_mock.CoroutineMock(
                return_value=(px_rec_instance, "pres message")
            )
            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_pres_mgr.return_value.create_pres.assert_called_once()

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            px_rec_instance
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "pres message"
        assert target == {}

    async def test_called_auto_present_no_preview(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=INDY_PROOF_REQ
        )
        request_context.message_receipt = MessageReceipt()
        px_rec_instance = test_module.V20PresExRecord(auto_present=True)

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module, "IndyHolder", autospec=True
        ) as mock_holder:

            mock_holder.get_credentials_for_presentation_request_by_referent = (
                async_mock.CoroutineMock(
                    return_value=[
                        {"cred_info": {"referent": "dummy-0"}},
                        {"cred_info": {"referent": "dummy-1"}},
                    ]
                )
            )
            request_context.inject = async_mock.MagicMock(return_value=mock_holder)

            mock_pres_ex_rec_cls.return_value = px_rec_instance
            mock_pres_ex_rec_cls.retrieve_by_tag_filter = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )
            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )

            mock_pres_mgr.return_value.create_pres = async_mock.CoroutineMock(
                return_value=(px_rec_instance, "pres message")
            )
            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_pres_mgr.return_value.create_pres.assert_called_once()

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            px_rec_instance
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "pres message"
        assert target == {}

    async def test_called_auto_present_pred_no_match(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=INDY_PROOF_REQ_PRED
        )
        request_context.message_receipt = MessageReceipt()
        px_rec_instance = test_module.V20PresExRecord(auto_present=True)

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module, "IndyHolder", autospec=True
        ) as mock_holder:

            mock_holder.get_credentials_for_presentation_request_by_referent = (
                async_mock.CoroutineMock(return_value=[])
            )
            request_context.inject = async_mock.MagicMock(return_value=mock_holder)

            mock_pres_ex_rec_cls.return_value = px_rec_instance
            mock_pres_ex_rec_cls.retrieve_by_tag_filter = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )
            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )

            mock_pres_mgr.return_value.create_pres = async_mock.CoroutineMock(
                return_value=(px_rec_instance, "pres message")
            )
            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_pres_mgr.return_value.create_pres.assert_not_called()

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            px_rec_instance
        )
        assert not responder.messages

    async def test_called_auto_present_pred_single_match(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=INDY_PROOF_REQ_PRED
        )
        request_context.message_receipt = MessageReceipt()
        px_rec_instance = test_module.V20PresExRecord(auto_present=True)

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module, "IndyHolder", autospec=True
        ) as mock_holder:

            mock_holder.get_credentials_for_presentation_request_by_referent = (
                async_mock.CoroutineMock(
                    return_value=[{"cred_info": {"referent": "dummy-0"}}]
                )
            )
            request_context.inject = async_mock.MagicMock(return_value=mock_holder)

            mock_pres_ex_rec_cls.return_value = px_rec_instance
            mock_pres_ex_rec_cls.retrieve_by_tag_filter = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )
            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )

            mock_pres_mgr.return_value.create_pres = async_mock.CoroutineMock(
                return_value=(px_rec_instance, "pres message")
            )
            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_pres_mgr.return_value.create_pres.assert_called_once()

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            px_rec_instance
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "pres message"
        assert target == {}

    async def test_called_auto_present_pred_multi_match(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=INDY_PROOF_REQ_PRED
        )
        request_context.message_receipt = MessageReceipt()
        px_rec_instance = test_module.V20PresExRecord(auto_present=True)

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module, "IndyHolder", autospec=True
        ) as mock_holder:

            mock_holder.get_credentials_for_presentation_request_by_referent = (
                async_mock.CoroutineMock(
                    return_value=[
                        {"cred_info": {"referent": "dummy-0"}},
                        {"cred_info": {"referent": "dummy-1"}},
                    ]
                )
            )
            request_context.inject = async_mock.MagicMock(return_value=mock_holder)

            mock_pres_ex_rec_cls.return_value = px_rec_instance
            mock_pres_ex_rec_cls.retrieve_by_tag_filter = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )
            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )

            mock_pres_mgr.return_value.create_pres = async_mock.CoroutineMock(
                return_value=(px_rec_instance, "pres message")
            )
            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_pres_mgr.return_value.create_pres.assert_called_once()

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            px_rec_instance
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "pres message"
        assert target == {}

    async def test_called_auto_present_multi_cred_match_reft(self):
        request_context = RequestContext.test_context()
        request_context.connection_record = async_mock.MagicMock()
        request_context.connection_record.connection_id = "dummy"
        request_context.message = V20PresRequest()
        request_context.message.attachment = async_mock.MagicMock(
            return_value=INDY_PROOF_REQ
        )
        request_context.message_receipt = MessageReceipt()
        pres_proposal = V20PresProposal(
            formats=[
                V20PresFormat(
                    attach_id="indy",
                    format_=V20PresFormat.Format.INDY.aries,
                )
            ],
            proposals_attach=[
                AttachDecorator.data_base64(INDY_PROOF_REQ, ident="indy")
            ],
        )

        px_rec_instance = test_module.V20PresExRecord(
            pres_proposal=pres_proposal.serialize(),
            auto_present=True,
        )
        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr, async_mock.patch.object(
            test_module, "V20PresExRecord", autospec=True
        ) as mock_pres_ex_rec_cls, async_mock.patch.object(
            test_module, "IndyHolder", autospec=True
        ) as mock_holder:

            mock_holder.get_credentials_for_presentation_request_by_referent = (
                async_mock.CoroutineMock(
                    return_value=[
                        {
                            "cred_info": {
                                "referent": "dummy-0",
                                "cred_def_id": CD_ID,
                                "attrs": {
                                    "ident": "zero",
                                    "favourite": "potato",
                                    "icon": "cG90YXRv",
                                },
                            }
                        },
                        {
                            "cred_info": {
                                "referent": "dummy-1",
                                "cred_def_id": CD_ID,
                                "attrs": {
                                    "ident": "one",
                                    "favourite": "spud",
                                    "icon": "c3B1ZA==",
                                },
                            }
                        },
                        {
                            "cred_info": {
                                "referent": "dummy-2",
                                "cred_def_id": CD_ID,
                                "attrs": {
                                    "ident": "two",
                                    "favourite": "patate",
                                    "icon": "cGF0YXRl",
                                },
                            }
                        },
                    ]
                )
            )
            request_context.inject = async_mock.MagicMock(return_value=mock_holder)

            mock_pres_ex_rec_cls.return_value = px_rec_instance
            mock_pres_ex_rec_cls.retrieve_by_tag_filter = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )
            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock(
                return_value=px_rec_instance
            )

            mock_pres_mgr.return_value.create_pres = async_mock.CoroutineMock(
                return_value=(px_rec_instance, "pres message")
            )
            request_context.connection_ready = True
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_pres_mgr.return_value.create_pres.assert_called_once()

        mock_pres_mgr.return_value.receive_pres_request.assert_called_once_with(
            px_rec_instance
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "pres message"
        assert target == {}

    async def test_called_not_ready(self):
        request_context = RequestContext.test_context()
        request_context.message_receipt = MessageReceipt()

        with async_mock.patch.object(
            test_module, "V20PresManager", autospec=True
        ) as mock_pres_mgr:
            mock_pres_mgr.return_value.receive_pres_request = async_mock.CoroutineMock()
            request_context.message = V20PresRequest()
            request_context.connection_ready = False
            handler_inst = test_module.V20PresRequestHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException):
                await handler_inst.handle(request_context, responder)

        assert not responder.messages
