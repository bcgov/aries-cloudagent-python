import pytest

from acapy_agent.tests import mock

from ......connections.models import connection_target
from ......connections.models.diddoc import DIDDoc, PublicKey, PublicKeyType, Service
from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......protocols.trustping.v1_0.messages.ping import Ping
from ......transport.inbound.receipt import MessageReceipt
from ......utils.testing import create_test_profile
from ...handlers import connection_response_handler as handler
from ...manager import ConnectionManagerError
from ...messages.connection_response import ConnectionResponse
from ...messages.problem_report import ConnectionProblemReport, ProblemReportReason
from ...models.connection_detail import ConnectionDetail


@pytest.fixture()
async def request_context():
    ctx = RequestContext.test_context(await create_test_profile())
    ctx.message_receipt = MessageReceipt()
    yield ctx


TEST_DID = "55GkHamhTU1ZbTbV2ab9DE"
TEST_VERKEY = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
TEST_LABEL = "Label"
TEST_ENDPOINT = "http://localhost"
TEST_IMAGE_URL = "http://aries.ca/images/sample.png"


@pytest.fixture()
def did_doc():
    doc = DIDDoc(did=TEST_DID)
    controller = TEST_DID
    ident = "1"
    pk_value = TEST_VERKEY
    pk = PublicKey(
        TEST_DID,
        ident,
        pk_value,
        PublicKeyType.ED25519_SIG_2018,
        controller,
        False,
    )
    doc.set(pk)
    recip_keys = [pk]
    router_keys = []
    service = Service(
        TEST_DID,
        "indy",
        "IndyAgent",
        recip_keys,
        router_keys,
        TEST_ENDPOINT,
    )
    doc.set(service)
    yield doc


class TestResponseHandler:
    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    async def test_called(self, mock_conn_mgr, request_context):
        mock_conn_mgr.return_value.accept_response = mock.CoroutineMock()
        request_context.message = ConnectionResponse()
        handler_inst = handler.ConnectionResponseHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        mock_conn_mgr.return_value.accept_response.assert_called_once_with(
            request_context.message, request_context.message_receipt
        )
        assert not responder.messages

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    async def test_called_auto_ping(self, mock_conn_mgr, request_context):
        request_context.update_settings({"auto_ping_connection": True})
        mock_conn_mgr.return_value.accept_response = mock.CoroutineMock()
        request_context.message = ConnectionResponse()
        handler_inst = handler.ConnectionResponseHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        mock_conn_mgr.return_value.accept_response.assert_called_once_with(
            request_context.message, request_context.message_receipt
        )
        messages = responder.messages
        assert len(messages) == 1
        result, _ = messages[0]
        assert isinstance(result, Ping)

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    @mock.patch.object(connection_target, "ConnectionTarget")
    async def test_problem_report(self, mock_conn_target, mock_conn_mgr, request_context):
        mock_conn_mgr.return_value.accept_response = mock.CoroutineMock()
        mock_conn_mgr.return_value.accept_response.side_effect = ConnectionManagerError(
            error_code=ProblemReportReason.RESPONSE_NOT_ACCEPTED.value,
        )
        mock_conn_mgr.return_value.manager_error_to_problem_report = mock.MagicMock(
            return_value=(
                ConnectionProblemReport(
                    description={
                        "en": "test error",
                        "code": ProblemReportReason.RESPONSE_NOT_ACCEPTED.value,
                    }
                ),
                [mock_conn_target],
            )
        )
        request_context.message = ConnectionResponse()
        handler_inst = handler.ConnectionResponseHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        messages = responder.messages
        assert len(messages) == 1
        result, target = messages[0]
        assert (
            isinstance(result, ConnectionProblemReport)
            and result.description
            and (
                result.description["code"]
                == ProblemReportReason.RESPONSE_NOT_ACCEPTED.value
            )
        )
        assert target == {"target_list": [mock_conn_target]}

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    @mock.patch.object(connection_target, "ConnectionTarget")
    async def test_problem_report_did_doc(
        self, mock_conn_target, mock_conn_mgr, request_context, did_doc
    ):
        mock_conn_mgr.return_value.accept_response = mock.CoroutineMock()
        mock_conn_mgr.return_value.accept_response.side_effect = ConnectionManagerError(
            error_code=ProblemReportReason.RESPONSE_NOT_ACCEPTED.value,
        )
        mock_conn_mgr.return_value.diddoc_connection_targets = mock.MagicMock(
            return_value=[mock_conn_target]
        )
        mock_conn_mgr.return_value.manager_error_to_problem_report = mock.MagicMock(
            return_value=(
                ConnectionProblemReport(
                    description={
                        "en": "test error",
                        "code": ProblemReportReason.RESPONSE_NOT_ACCEPTED.value,
                    }
                ),
                [mock_conn_target],
            )
        )
        request_context.message = ConnectionResponse(
            connection=ConnectionDetail(did=TEST_DID, did_doc=did_doc)
        )
        handler_inst = handler.ConnectionResponseHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        messages = responder.messages
        assert len(messages) == 1
        result, target = messages[0]
        assert (
            isinstance(result, ConnectionProblemReport)
            and result.description
            and (
                result.description["code"]
                == ProblemReportReason.RESPONSE_NOT_ACCEPTED.value
            )
        )
        assert target == {"target_list": [mock_conn_target]}

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    @mock.patch.object(connection_target, "ConnectionTarget")
    async def test_problem_report_did_doc_no_conn_target(
        self, mock_conn_target, mock_conn_mgr, request_context, did_doc
    ):
        mock_conn_mgr.return_value.accept_response = mock.CoroutineMock()
        mock_conn_mgr.return_value.accept_response.side_effect = ConnectionManagerError(
            error_code=ProblemReportReason.RESPONSE_NOT_ACCEPTED.value,
        )
        mock_conn_mgr.return_value.diddoc_connection_targets = mock.MagicMock(
            side_effect=ConnectionManagerError("no target")
        )
        mock_conn_mgr.return_value.manager_error_to_problem_report = mock.MagicMock(
            return_value=(
                ConnectionProblemReport(
                    description={
                        "en": "test error",
                        "code": ProblemReportReason.RESPONSE_NOT_ACCEPTED.value,
                    }
                ),
                None,
            )
        )
        request_context.message = ConnectionResponse(
            connection=ConnectionDetail(did=TEST_DID, did_doc=did_doc)
        )
        handler_inst = handler.ConnectionResponseHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        messages = responder.messages
        assert len(messages) == 0  # need a connection target to send message
