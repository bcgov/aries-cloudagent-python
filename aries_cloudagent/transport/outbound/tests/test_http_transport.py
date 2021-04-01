import asyncio
import pytest

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp import web
from asynctest import mock as async_mock

from ....core.in_memory import InMemoryProfile
from ....utils.stats import Collector

from ...wire_format import JsonWireFormat

from ..base import OutboundTransportError
from ..http import HttpTransport


class TestHttpTransport(AioHTTPTestCase):
    async def setUpAsync(self):
        self.profile = InMemoryProfile.test_profile()
        self.message_results = []
        self.headers = {}

    async def receive_message(self, request):
        payload = await request.json()
        self.headers = request.headers
        self.message_results.append(payload)
        raise web.HTTPOk()

    async def get_application(self):
        """
        Override the get_app method to return your application.
        """
        app = web.Application()
        app.add_routes([web.post("/", self.receive_message)])
        return app

    @unittest_run_loop
    async def test_handle_message_no_api_key(self):
        server_addr = f"http://localhost:{self.server.port}"

        async def send_message(transport, payload, endpoint):
            async with transport:
                await transport.handle_message(self.profile, payload, endpoint)

        transport = HttpTransport()

        await asyncio.wait_for(send_message(transport, "{}", endpoint=server_addr), 5.0)
        assert self.message_results == [{}]
        assert self.headers.get("x-api-key") is None
        assert self.headers.get("content-type") == "application/json"

    @unittest_run_loop
    async def test_handle_message_api_key(self):
        server_addr = f"http://localhost:{self.server.port}"
        api_key = "test1234"

        async def send_message(transport, payload, endpoint, api_key):
            async with transport:
                await transport.handle_message(
                    self.profile, payload, endpoint, api_key=api_key
                )

        transport = HttpTransport()

        await asyncio.wait_for(
            send_message(transport, "{}", endpoint=server_addr, api_key=api_key), 5.0
        )
        assert self.message_results == [{}]
        assert self.headers.get("x-api-key") == api_key

    @unittest_run_loop
    async def test_handle_message_packed_compat_mime_type(self):
        server_addr = f"http://localhost:{self.server.port}"

        async def send_message(transport, payload, endpoint):
            async with transport:
                await transport.handle_message(self.profile, payload, endpoint)

        transport = HttpTransport()

        await asyncio.wait_for(
            send_message(transport, b"{}", endpoint=server_addr), 5.0
        )
        assert self.message_results == [{}]
        assert self.headers.get("content-type") == "application/ssi-agent-wire"

    @unittest_run_loop
    async def test_handle_message_packed_standard_mime_type(self):
        server_addr = f"http://localhost:{self.server.port}"

        async def send_message(transport, payload, endpoint):
            async with transport:
                await transport.handle_message(self.profile, payload, endpoint)

        transport = HttpTransport()

        self.profile.settings["aip_version"] = 2
        await asyncio.wait_for(
            send_message(transport, b"{}", endpoint=server_addr), 5.0
        )
        assert self.message_results == [{}]
        assert self.headers.get("content-type") == "application/didcomm-envelope-enc"

    @unittest_run_loop
    async def test_stats(self):
        server_addr = f"http://localhost:{self.server.port}"

        async def send_message(transport, payload, endpoint):
            async with transport:
                await transport.handle_message(self.profile, payload, endpoint)

        transport = HttpTransport()
        transport.collector = Collector()
        await asyncio.wait_for(
            send_message(transport, b"{}", endpoint=server_addr), 5.0
        )

        results = transport.collector.extract()
        assert results["count"] == {
            "outbound-http:dns_resolve": 1,
            "outbound-http:connect": 1,
            "outbound-http:POST": 1,
        }

    @unittest_run_loop
    async def test_transport_coverage(self):
        transport = HttpTransport()
        assert transport.wire_format is None
        transport.wire_format = JsonWireFormat()
        assert transport.wire_format is not None

        await transport.start()

        with pytest.raises(OutboundTransportError):
            await transport.handle_message(None, None, None)

        with async_mock.patch.object(
            transport, "client_session", async_mock.MagicMock()
        ) as mock_session:
            mock_response = async_mock.MagicMock(status=404)
            mock_session.post = async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    __aenter__=async_mock.CoroutineMock(return_value=mock_response)
                )
            )
            with pytest.raises(OutboundTransportError):
                await transport.handle_message(None, "dummy", "http://localhost")

        await transport.__aexit__(KeyError, KeyError("just a drill"), None)
