import gc
import json
from typing import Optional
from unittest import IsolatedAsyncioTestCase

import jwt
import pytest
from aiohttp import ClientSession, DummyCookieJar, TCPConnector, web
from aiohttp.test_utils import unused_port
from marshmallow import ValidationError

from ...askar.profile import AskarProfile
from ...config.default_context import DefaultContextBuilder
from ...config.injection_context import InjectionContext
from ...core.event_bus import Event
from ...core.goal_code_registry import GoalCodeRegistry
from ...core.protocol_registry import ProtocolRegistry
from ...didcomm_v2.protocol_registry import V2ProtocolRegistry
from ...multitenant.error import MultitenantManagerError
from ...storage.base import BaseStorage
from ...storage.error import StorageNotFoundError
from ...storage.record import StorageRecord
from ...storage.type import RECORD_TYPE_ACAPY_UPGRADING
from ...tests import mock
from ...utils.stats import Collector
from ...utils.task_queue import TaskQueue
from ...utils.testing import create_test_profile
from ...wallet import singletons
from ...wallet.anoncreds_upgrade import UPGRADING_RECORD_IN_PROGRESS
from .. import server as test_module
from ..request_context import AdminRequestContext
from ..server import AdminServer, AdminSetupError


# Ignore Marshmallow warning, as well as 'NotAppKeyWarning' coming from apispec packages
@pytest.mark.filterwarnings(
    "ignore:The 'missing' attribute of fields is deprecated. Use 'load_default' instead.",
    "ignore:It is recommended to use web.AppKey instances for keys.",
)
class TestAdminServer(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.message_results = []
        self.webhook_results = []
        self.port = 0

        self.connector = TCPConnector(limit=16, limit_per_host=4)
        self.client_session = ClientSession(
            cookie_jar=DummyCookieJar(), connector=self.connector
        )

    async def test_debug_middleware(self):
        with mock.patch.object(test_module, "LOGGER", mock.MagicMock()) as mock_logger:
            mock_logger.isEnabledFor = mock.MagicMock(return_value=True)
            mock_logger.debug = mock.MagicMock()

            request = mock.MagicMock(
                method="GET",
                path_qs="/hello/world?a=1&b=2",
                match_info={"match": "info"},
                text=mock.CoroutineMock(return_value="abc123"),
            )
            handler = mock.CoroutineMock()

            await test_module.debug_middleware(request, handler)
            mock_logger.isEnabledFor.assert_called_once()
            assert mock_logger.debug.call_count == 3

    async def test_ready_middleware(self):
        with mock.patch.object(test_module, "LOGGER", mock.MagicMock()) as mock_logger:
            mock_logger.isEnabledFor = mock.MagicMock(return_value=True)
            mock_logger.debug = mock.MagicMock()
            mock_logger.info = mock.MagicMock()
            mock_logger.error = mock.MagicMock()

            request = mock.MagicMock(
                rel_url="/", app=mock.MagicMock(_state={"ready": False})
            )
            handler = mock.CoroutineMock(return_value="OK")
            with self.assertRaises(test_module.web.HTTPServiceUnavailable):
                await test_module.ready_middleware(request, handler)

            request.app._state["ready"] = True
            assert await test_module.ready_middleware(request, handler) == "OK"

            request.app._state["ready"] = True
            handler = mock.CoroutineMock(
                side_effect=test_module.LedgerConfigError("Bad config")
            )
            with self.assertRaises(test_module.LedgerConfigError):
                await test_module.ready_middleware(request, handler)

            request.app._state["ready"] = True
            handler = mock.CoroutineMock(
                side_effect=test_module.web.HTTPFound(location="/api/doc")
            )
            with self.assertRaises(test_module.web.HTTPFound):
                await test_module.ready_middleware(request, handler)

            request.app._state["ready"] = True
            handler = mock.CoroutineMock(
                side_effect=test_module.asyncio.CancelledError("Cancelled")
            )
            with self.assertRaises(test_module.asyncio.CancelledError):
                await test_module.ready_middleware(request, handler)

            request.app._state["ready"] = True
            handler = mock.CoroutineMock(side_effect=KeyError("No such thing"))
            with self.assertRaises(KeyError):
                await test_module.ready_middleware(request, handler)

    async def test_ready_middleware_http_unauthorized(self):
        """Test handling of web.HTTPUnauthorized and related exceptions."""
        with mock.patch.object(test_module, "LOGGER", mock.MagicMock()) as mock_logger:
            mock_logger.info = mock.MagicMock()

            request = mock.MagicMock(
                method="GET",
                path="/unauthorized",
                app=mock.MagicMock(_state={"ready": True}),
            )

            # Test web.HTTPUnauthorized
            handler = mock.CoroutineMock(
                side_effect=web.HTTPUnauthorized(reason="Unauthorized")
            )
            with self.assertRaises(web.HTTPUnauthorized):
                await test_module.ready_middleware(request, handler)
            mock_logger.info.assert_called_with(
                "Unauthorized access during %s %s: %s",
                request.method,
                request.path,
                handler.side_effect,
            )

            # Test jwt.InvalidTokenError
            handler = mock.CoroutineMock(
                side_effect=jwt.InvalidTokenError("Invalid token")
            )
            with self.assertRaises(web.HTTPUnauthorized):
                await test_module.ready_middleware(request, handler)
            mock_logger.info.assert_called_with(
                "Unauthorized access during %s %s: %s",
                request.method,
                request.path,
                handler.side_effect,
            )

            # Test InvalidTokenError
            handler = mock.CoroutineMock(
                side_effect=test_module.InvalidTokenError("Token error")
            )
            with self.assertRaises(web.HTTPUnauthorized):
                await test_module.ready_middleware(request, handler)
            mock_logger.info.assert_called_with(
                "Unauthorized access during %s %s: %s",
                request.method,
                request.path,
                handler.side_effect,
            )

    async def test_ready_middleware_http_bad_request(self):
        """Test handling of web.HTTPBadRequest and MultitenantManagerError."""
        with mock.patch.object(test_module, "LOGGER", mock.MagicMock()) as mock_logger:
            mock_logger.info = mock.MagicMock()

            request = mock.MagicMock(
                method="POST",
                path="/bad-request",
                app=mock.MagicMock(_state={"ready": True}),
            )

            # Test web.HTTPBadRequest
            handler = mock.CoroutineMock(
                side_effect=web.HTTPBadRequest(reason="Bad request")
            )
            with self.assertRaises(web.HTTPBadRequest):
                await test_module.ready_middleware(request, handler)
            mock_logger.info.assert_called_with(
                "Bad request during %s %s: %s",
                request.method,
                request.path,
                handler.side_effect,
            )

            # Test MultitenantManagerError
            handler = mock.CoroutineMock(
                side_effect=MultitenantManagerError("Multitenant error")
            )
            with self.assertRaises(web.HTTPBadRequest):
                await test_module.ready_middleware(request, handler)
            mock_logger.info.assert_called_with(
                "Bad request during %s %s: %s",
                request.method,
                request.path,
                handler.side_effect,
            )

    async def test_ready_middleware_http_not_found(self):
        """Test handling of web.HTTPNotFound and StorageNotFoundError."""
        with mock.patch.object(test_module, "LOGGER", mock.MagicMock()) as mock_logger:
            mock_logger.info = mock.MagicMock()

            request = mock.MagicMock(
                method="GET",
                path="/not-found",
                app=mock.MagicMock(_state={"ready": True}),
            )

            # Test web.HTTPNotFound
            handler = mock.CoroutineMock(side_effect=web.HTTPNotFound(reason="Not found"))
            with self.assertRaises(web.HTTPNotFound):
                await test_module.ready_middleware(request, handler)
            mock_logger.info.assert_called_with(
                "Not Found error occurred during %s %s: %s",
                request.method,
                request.path,
                handler.side_effect,
            )

            # Test StorageNotFoundError
            handler = mock.CoroutineMock(
                side_effect=StorageNotFoundError("Item not found")
            )
            with self.assertRaises(web.HTTPNotFound):
                await test_module.ready_middleware(request, handler)
            mock_logger.info.assert_called_with(
                "Not Found error occurred during %s %s: %s",
                request.method,
                request.path,
                handler.side_effect,
            )

    async def test_ready_middleware_http_unprocessable_entity(self):
        """Test handling of web.HTTPUnprocessableEntity with nested ValidationError."""
        with mock.patch.object(test_module, "LOGGER", mock.MagicMock()) as mock_logger:
            mock_logger.info = mock.MagicMock()
            # Mock the extract_validation_error_message function
            with mock.patch.object(
                test_module, "extract_validation_error_message"
            ) as mock_extract:
                mock_extract.return_value = {"field": ["Invalid input"]}

                request = mock.MagicMock(
                    method="POST",
                    path="/unprocessable",
                    app=mock.MagicMock(_state={"ready": True}),
                )

                # Create a HTTPUnprocessableEntity exception with a nested ValidationError
                validation_error = ValidationError({"field": ["Invalid input"]})
                http_error = web.HTTPUnprocessableEntity(reason="Unprocessable Entity")
                http_error.__cause__ = validation_error

                handler = mock.CoroutineMock(side_effect=http_error)
                with self.assertRaises(web.HTTPUnprocessableEntity):
                    await test_module.ready_middleware(request, handler)
                mock_extract.assert_called_once_with(http_error)
                mock_logger.info.assert_called_with(
                    "Unprocessable Entity occurred during %s %s: %s",
                    request.method,
                    request.path,
                    mock_extract.return_value,
                )

    async def get_admin_server(
        self, settings: Optional[dict] = None, context: Optional[InjectionContext] = None
    ) -> AdminServer:
        if not context:
            context = InjectionContext()
        if settings:
            context.update_settings(settings)

        # middleware is task queue xor collector: cover both over test suite
        task_queue = (settings or {}).pop("task_queue", None)

        plugin_registry = mock.MagicMock(test_module.PluginRegistry, autospec=True)
        plugin_registry.post_process_routes = mock.MagicMock()
        context.injector.bind_instance(test_module.PluginRegistry, plugin_registry)
        context.injector.bind_instance(test_module.Collector, Collector())

        self.profile = await create_test_profile(settings=settings)

        self.port = unused_port()
        return AdminServer(
            "0.0.0.0",
            self.port,
            context,
            self.profile,
            self.outbound_message_router,
            self.webhook_router,
            conductor_stop=mock.CoroutineMock(),
            task_queue=TaskQueue(max_active=4) if task_queue else None,
            conductor_stats=(
                None if task_queue else mock.CoroutineMock(return_value={"a": 1})
            ),
        )

    async def outbound_message_router(self, *args):
        self.message_results.append(args)

    def webhook_router(self, *args):
        self.webhook_results.append(args)

    async def test_start_stop(self):
        with self.assertRaises(AssertionError):
            await (await self.get_admin_server()).start()

        settings = {"admin.admin_insecure_mode": False}
        with self.assertRaises(AssertionError):
            await (await self.get_admin_server(settings)).start()

        settings = {
            "admin.admin_insecure_mode": True,
            "admin.admin_api_key": "test-api-key",
        }
        with self.assertRaises(AssertionError):
            await (await self.get_admin_server(settings)).start()

        settings = {
            "admin.admin_insecure_mode": False,
            "admin.admin_client_max_request_size": 4,
            "admin.admin_api_key": "test-api-key",
        }
        server = await self.get_admin_server(settings)
        await server.start()
        assert server.app._client_max_size == 4 * 1024 * 1024
        with mock.patch.object(server, "websocket_queues", mock.MagicMock()) as mock_wsq:
            mock_wsq.values = mock.MagicMock(
                return_value=[mock.MagicMock(stop=mock.MagicMock())]
            )
            await server.stop()

        with mock.patch.object(web.TCPSite, "start", mock.CoroutineMock()) as mock_start:
            mock_start.side_effect = OSError("Failure to launch")
            with self.assertRaises(AdminSetupError):
                await (await self.get_admin_server(settings)).start()

    async def test_import_routes(self):
        # this test just imports all default admin routes
        # for routes with associated tests, this shouldn't make a difference in coverage
        context = InjectionContext()
        context.injector.bind_instance(ProtocolRegistry, ProtocolRegistry())
        context.injector.bind_instance(V2ProtocolRegistry, V2ProtocolRegistry())
        context.injector.bind_instance(GoalCodeRegistry, GoalCodeRegistry())
        await DefaultContextBuilder().load_plugins(context)
        server = await self.get_admin_server({"admin.admin_insecure_mode": True}, context)
        await server.make_application()

    async def test_register_external_plugin_x(self):
        context = InjectionContext()
        context.injector.bind_instance(ProtocolRegistry, ProtocolRegistry())
        context.injector.bind_instance(V2ProtocolRegistry, V2ProtocolRegistry())
        context.injector.bind_instance(GoalCodeRegistry, GoalCodeRegistry())
        with self.assertLogs(level="ERROR") as logs:
            builder = DefaultContextBuilder(
                settings={"external_plugins": ["acapy_agent.nosuchmodule"]}
            )
            await builder.load_plugins(context)
        assert "Module doesn't exist: acapy_agent.nosuchmodule" in "\n".join(logs.output)

    async def test_visit_insecure_mode(self):
        settings = {"admin.admin_insecure_mode": True, "task_queue": True}
        server = await self.get_admin_server(settings)
        await server.start()

        async with self.client_session.post(
            f"http://127.0.0.1:{self.port}/status/reset", headers={}
        ) as response:
            assert response.status == 200

        async with self.client_session.ws_connect(
            f"http://127.0.0.1:{self.port}/ws"
        ) as ws:
            result = await ws.receive_json()
            assert result["topic"] == "settings"

        for path in (
            "",
            "plugins",
            "status",
            "status/live",
            "status/ready",
            "shutdown",  # mock conductor has magic-mock stop()
        ):
            async with self.client_session.get(
                f"http://127.0.0.1:{self.port}/{path}", headers={}
            ) as response:
                assert response.status == 200

        await server.stop()

    async def test_visit_secure_mode(self):
        settings = {
            "admin.admin_insecure_mode": False,
            "admin.admin_api_key": "test-api-key",
        }
        server = await self.get_admin_server(settings)
        await server.start()

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status", headers={"x-api-key": "wrong-key"}
        ) as response:
            assert response.status == 401

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status",
            headers={"x-api-key": "test-api-key"},
        ) as response:
            assert response.status == 200

        # Make sure that OPTIONS requests used by browsers for CORS
        # are allowed without a x-api-key even when x-api-key security is enabled
        async with self.client_session.options(
            f"http://127.0.0.1:{self.port}/status",
            headers={
                "Access-Control-Request-Headers": "x-api-key",
                "Access-Control-Request-Method": "GET",
                "Connection": "keep-alive",
                "Host": f"http://127.0.0.1:{self.port}/status",
                "Origin": "http://localhost:3000",
                "Referer": "http://localhost:3000/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
            },
        ) as response:
            assert response.status == 200
            assert response.headers["Access-Control-Allow-Credentials"] == "true"
            assert response.headers["Access-Control-Allow-Headers"] == "X-API-KEY"
            assert response.headers["Access-Control-Allow-Methods"] == "GET"
            assert (
                response.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
            )

        async with self.client_session.ws_connect(
            f"http://127.0.0.1:{self.port}/ws", headers={"x-api-key": "test-api-key"}
        ) as ws:
            result = await ws.receive_json()
            assert result["topic"] == "settings"

        await server.stop()

    async def test_query_config(self):
        settings = {
            "admin.admin_insecure_mode": False,
            "admin.admin_api_key": "test-api-key",
            "admin.webhook_urls": ["localhost:8123/abc#secret", "localhost:8123/def"],
            "multitenant.jwt_secret": "abc123",
            "wallet.key": "abc123",
            "wallet.rekey": "def456",
            "wallet.seed": "00000000000000000000000000000000",
            "wallet.storage.creds": "secret",
        }
        server = await self.get_admin_server(settings)
        await server.start()

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status/config",
            headers={"x-api-key": "test-api-key"},
        ) as response:
            config = json.loads(await response.text())["config"]
            assert "admin.admin_insecure_mode" in config
            assert all(
                k not in config
                for k in [
                    "admin.admin_api_key",
                    "multitenant.jwt_secret",
                    "wallet.key",
                    "wallet.rekey",
                    "wallet.seed",
                    "wallet.storage_creds",
                ]
            )
            assert config["admin.webhook_urls"] == [
                "localhost:8123/abc",
                "localhost:8123/def",
            ]

    async def test_visit_shutting_down(self):
        settings = {
            "admin.admin_insecure_mode": True,
        }
        server = await self.get_admin_server(settings)
        await server.start()

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/shutdown", headers={}
        ) as response:
            assert response.status == 200

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status", headers={}
        ) as response:
            assert response.status == 503

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status/live", headers={}
        ) as response:
            assert response.status == 200
        await server.stop()

    async def test_server_health_state(self):
        settings = {
            "admin.admin_insecure_mode": True,
        }
        server = await self.get_admin_server(settings)
        await server.start()

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status/live", headers={}
        ) as response:
            assert response.status == 200
            response_json = await response.json()
            assert response_json["alive"]

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status/ready", headers={}
        ) as response:
            assert response.status == 200
            response_json = await response.json()
            assert response_json["ready"]

        server.notify_fatal_error()
        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status/live", headers={}
        ) as response:
            assert response.status == 503

        async with self.client_session.get(
            f"http://127.0.0.1:{self.port}/status/ready", headers={}
        ) as response:
            assert response.status == 503
        await server.stop()

    async def test_upgrade_middleware(self):
        profile = await create_test_profile()
        self.context = AdminRequestContext.test_context({}, profile)
        self.request_dict = {
            "context": self.context,
        }
        request = mock.MagicMock(
            method="GET",
            path_qs="/schemas/created",
            match_info={},
            __getitem__=lambda _, k: self.request_dict[k],
        )
        handler = mock.CoroutineMock()

        await test_module.upgrade_middleware(request, handler)

        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            upgrading_record = StorageRecord(
                RECORD_TYPE_ACAPY_UPGRADING,
                UPGRADING_RECORD_IN_PROGRESS,
            )
            # No upgrade in progress
            await storage.add_record(upgrading_record)

            # Upgrade in progress without cache
            with self.assertRaises(test_module.web.HTTPServiceUnavailable):
                await test_module.upgrade_middleware(request, handler)

            # Upgrade in progress with cache
            singletons.UpgradeInProgressSingleton().set_wallet(profile.name)
            with self.assertRaises(test_module.web.HTTPServiceUnavailable):
                await test_module.upgrade_middleware(request, handler)

            singletons.UpgradeInProgressSingleton().remove_wallet(profile.name)
            await storage.delete_record(upgrading_record)

            # Upgrade in progress with cache
            singletons.IsAnoncredsSingleton().set_wallet(profile.name)
            await test_module.upgrade_middleware(request, handler)


@pytest.fixture
async def server():
    test_class = TestAdminServer()
    await test_class.asyncSetUp()
    yield test_class.get_admin_server()
    await test_class.asyncTearDown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_topic, webhook_topic",
    [("acapy::record::topic", "topic"), ("acapy::record::topic::state", "topic")],
)
async def test_on_record_event(server, event_topic, webhook_topic):
    profile = mock.MagicMock(AskarProfile, autospec=True)
    server = await server
    with mock.patch.object(
        server, "send_webhook", mock.CoroutineMock()
    ) as mock_send_webhook:
        await server._on_record_event(profile, Event(event_topic, None))
        mock_send_webhook.assert_called_once_with(profile, webhook_topic, None)


@pytest.mark.asyncio
async def test_admin_responder_profile_expired_x():
    async def _smaller_scope():
        profile = await create_test_profile()
        return test_module.AdminResponder(profile, None)

    responder = await _smaller_scope()
    gc.collect()  # help ensure collection of profile

    with pytest.raises(RuntimeError):
        await responder.send_outbound(None)

    with pytest.deprecated_call():
        with pytest.raises(RuntimeError):
            await responder.send_webhook("test", {})
