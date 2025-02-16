import pytest

from acapy_agent.tests import mock

from ......connections.models import connection_target
from ......connections.models.conn_record import ConnRecord
from ......connections.models.diddoc import DIDDoc, PublicKey, PublicKeyType, Service
from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......storage.base import BaseStorage
from ......storage.error import StorageNotFoundError
from ......transport.inbound.receipt import MessageReceipt
from ......utils.testing import create_test_profile
from ...handlers import connection_request_handler as handler
from ...manager import ConnectionManagerError
from ...messages.connection_request import ConnectionRequest
from ...messages.problem_report import ConnectionProblemReport, ProblemReportReason
from ...models.connection_detail import ConnectionDetail


@pytest.fixture()
async def request_context():
    ctx = RequestContext.test_context(await create_test_profile())
    ctx.message_receipt = MessageReceipt()
    yield ctx


@pytest.fixture()
async def session(request_context):
    yield await request_context.session()


@pytest.fixture()
async def connection_record(request_context, session):
    record = ConnRecord()
    request_context.connection_record = record
    await record.save(session)
    yield record


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


class TestRequestHandler:
    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    async def test_called(self, mock_conn_mgr, request_context):
        mock_conn_mgr.return_value.receive_request = mock.CoroutineMock()
        request_context.message = ConnectionRequest()
        handler_inst = handler.ConnectionRequestHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        mock_conn_mgr.return_value.receive_request.assert_called_once_with(
            request_context.message, request_context.message_receipt
        )
        assert not responder.messages

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    async def test_called_with_auto_response(self, mock_conn_mgr, request_context):
        mock_conn_rec = mock.MagicMock()
        mock_conn_rec.accept = ConnRecord.ACCEPT_AUTO
        mock_conn_mgr.return_value.receive_request = mock.CoroutineMock(
            return_value=mock_conn_rec
        )
        mock_conn_mgr.return_value.create_response = mock.CoroutineMock()
        request_context.message = ConnectionRequest()
        handler_inst = handler.ConnectionRequestHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        mock_conn_mgr.return_value.receive_request.assert_called_once_with(
            request_context.message, request_context.message_receipt
        )
        mock_conn_mgr.return_value.create_response.assert_called_once_with(
            mock_conn_rec, mediation_id=None
        )
        assert responder.messages

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    async def test_connection_record_with_mediation_metadata_auto_response(
        self, mock_conn_mgr, request_context, connection_record
    ):
        mock_conn_rec = mock.MagicMock()
        mock_conn_rec.accept = ConnRecord.ACCEPT_AUTO
        mock_conn_mgr.return_value.receive_request = mock.CoroutineMock(
            return_value=mock_conn_rec
        )
        mock_conn_mgr.return_value.create_response = mock.CoroutineMock()
        request_context.message = ConnectionRequest()
        with mock.patch.object(
            connection_record,
            "metadata_get",
            mock.CoroutineMock(return_value={"id": "test-mediation-id"}),
        ):
            handler_inst = handler.ConnectionRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_conn_mgr.return_value.receive_request.assert_called_once()
            mock_conn_mgr.return_value.create_response.assert_called_once_with(
                mock_conn_rec, mediation_id="test-mediation-id"
            )
            assert responder.messages

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    async def test_connection_record_without_mediation_metadata(
        self, mock_conn_mgr, request_context, session, connection_record
    ):
        mock_conn_mgr.return_value.receive_request = mock.CoroutineMock()
        request_context.message = ConnectionRequest()
        storage: BaseStorage = session.inject(BaseStorage)
        with mock.patch.object(
            storage,
            "find_record",
            mock.CoroutineMock(side_effect=StorageNotFoundError),
        ):
            handler_inst = handler.ConnectionRequestHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)
            mock_conn_mgr.return_value.receive_request.assert_called_once_with(
                request_context.message,
                request_context.message_receipt,
            )
            assert not responder.messages

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    @mock.patch.object(connection_target, "ConnectionTarget")
    async def test_problem_report(self, mock_conn_target, mock_conn_mgr, request_context):
        mock_conn_mgr.return_value.receive_request = mock.CoroutineMock()
        mock_conn_mgr.return_value.receive_request.side_effect = ConnectionManagerError(
            error_code=ProblemReportReason.REQUEST_NOT_ACCEPTED.value
        )
        mock_conn_mgr.return_value.manager_error_to_problem_report = mock.MagicMock(
            return_value=(
                ConnectionProblemReport(
                    description={
                        "en": "test error",
                        "code": ProblemReportReason.REQUEST_NOT_ACCEPTED.value,
                    }
                ),
                [mock_conn_target],
            )
        )
        request_context.message = ConnectionRequest()
        handler_inst = handler.ConnectionRequestHandler()
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
                == ProblemReportReason.REQUEST_NOT_ACCEPTED.value
            )
        )
        assert target == {"target_list": [mock_conn_target]}

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    @mock.patch.object(connection_target, "ConnectionTarget")
    async def test_problem_report_did_doc(
        self, mock_conn_target, mock_conn_mgr, request_context, did_doc
    ):
        mock_conn_mgr.return_value.receive_request = mock.CoroutineMock()
        mock_conn_mgr.return_value.receive_request.side_effect = ConnectionManagerError(
            error_code=ProblemReportReason.REQUEST_NOT_ACCEPTED.value
        )
        mock_conn_mgr.return_value.diddoc_connection_targets = mock.MagicMock(
            return_value=[mock_conn_target]
        )
        mock_conn_mgr.return_value.manager_error_to_problem_report = mock.MagicMock(
            return_value=(
                ConnectionProblemReport(
                    description={
                        "en": "test error",
                        "code": ProblemReportReason.REQUEST_NOT_ACCEPTED.value,
                    }
                ),
                [mock_conn_target],
            )
        )
        request_context.message = ConnectionRequest(
            connection=ConnectionDetail(did=TEST_DID, did_doc=did_doc),
            label=TEST_LABEL,
            image_url=TEST_IMAGE_URL,
        )
        handler_inst = handler.ConnectionRequestHandler()
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
                == ProblemReportReason.REQUEST_NOT_ACCEPTED.value
            )
        )
        assert target == {"target_list": [mock_conn_target]}

    @pytest.mark.asyncio
    @mock.patch.object(handler, "ConnectionManager")
    @mock.patch.object(connection_target, "ConnectionTarget")
    async def test_problem_report_did_doc_no_conn_target(
        self, mock_conn_target, mock_conn_mgr, request_context, did_doc
    ):
        mock_conn_mgr.return_value.receive_request = mock.CoroutineMock()
        mock_conn_mgr.return_value.receive_request.side_effect = ConnectionManagerError(
            error_code=ProblemReportReason.REQUEST_NOT_ACCEPTED.value
        )
        mock_conn_mgr.return_value.diddoc_connection_targets = mock.MagicMock(
            side_effect=ConnectionManagerError("no targets")
        )
        mock_conn_mgr.return_value.manager_error_to_problem_report = mock.MagicMock(
            return_value=(
                ConnectionProblemReport(
                    description={
                        "en": "test error",
                        "code": ProblemReportReason.REQUEST_NOT_ACCEPTED.value,
                    }
                ),
                None,
            )
        )
        request_context.message = ConnectionRequest(
            connection=ConnectionDetail(did=TEST_DID, did_doc=did_doc),
            label=TEST_LABEL,
            image_url=TEST_IMAGE_URL,
        )
        handler_inst = handler.ConnectionRequestHandler()
        responder = MockResponder()
        await handler_inst.handle(request_context, responder)
        messages = responder.messages
        assert len(messages) == 0  # messages require a target!
