from asynctest import (
    mock as async_mock,
    TestCase as AsyncTestCase,
)

from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......transport.inbound.receipt import MessageReceipt

from ...handlers import transaction_job_to_send_handler as test_module
from ...messages.transaction_job_to_send import TransactionJobToSend


class TestTransactionJobToSendHandler(AsyncTestCase):
    async def test_called(self):
        request_context = RequestContext.test_context()
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = async_mock.MagicMock()

        with async_mock.patch.object(
            test_module, "TransactionManager", autospec=True
        ) as mock_tran_mgr:
            mock_tran_mgr.return_value.set_transaction_their_job = (
                async_mock.CoroutineMock()
            )
            request_context.message = TransactionJobToSend()
            request_context.connection_ready = True
            handler = test_module.TransactionJobToSendHandler()
            handler._logger = async_mock.MagicMock(
                error=async_mock.MagicMock(),
                info=async_mock.MagicMock(),
                warning=async_mock.MagicMock(),
                debug=async_mock.MagicMock(),
            )
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_tran_mgr.return_value.set_transaction_their_job.assert_called_once_with(
            request_context.message, request_context.message_receipt
        )
        assert not responder.messages

    async def test_called_x(self):
        request_context = RequestContext.test_context()
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = async_mock.MagicMock()

        with async_mock.patch.object(
            test_module, "TransactionManager", autospec=True
        ) as mock_tran_mgr:
            mock_tran_mgr.return_value.set_transaction_their_job = (
                async_mock.CoroutineMock(
                    side_effect=test_module.TransactionManagerError()
                )
            )
            request_context.message = TransactionJobToSend()
            request_context.connection_ready = True
            handler = test_module.TransactionJobToSendHandler()
            handler._logger = async_mock.MagicMock(
                error=async_mock.MagicMock(),
                info=async_mock.MagicMock(),
                warning=async_mock.MagicMock(),
                debug=async_mock.MagicMock(),
            )
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_tran_mgr.return_value.set_transaction_their_job.assert_called_once_with(
            request_context.message, request_context.message_receipt
        )
        assert not responder.messages
