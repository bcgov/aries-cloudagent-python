"""Admin server classes."""

import asyncio
from hmac import compare_digest
import logging
import re
from typing import Callable, Coroutine
import uuid
import warnings

from aiohttp import web
from aiohttp_apispec import (
    docs,
    response_schema,
    setup_aiohttp_apispec,
    validation_middleware,
)
import aiohttp_cors
import jwt
from marshmallow import fields

from ..config.injection_context import InjectionContext
from ..core.event_bus import Event, EventBus
from ..core.plugin_registry import PluginRegistry
from ..core.profile import Profile
from ..ledger.error import LedgerConfigError, LedgerTransactionError
from ..messaging.models.openapi import OpenAPISchema
from ..messaging.responder import BaseResponder
from ..multitenant.manager import MultitenantManager, MultitenantManagerError
from ..storage.error import StorageNotFoundError
from ..transport.outbound.message import OutboundMessage
from ..transport.outbound.status import OutboundSendStatus
from ..transport.queue.basic import BasicMessageQueue
from ..utils.stats import Collector
from ..utils.task_queue import TaskQueue
from ..version import __version__
from .base_server import BaseAdminServer
from .error import AdminSetupError
from .request_context import AdminRequestContext

LOGGER = logging.getLogger(__name__)

EVENT_PATTERN_WEBHOOK = re.compile("^acapy::webhook::(.*)$")
EVENT_PATTERN_RECORD = re.compile("^acapy::record::([^:]*)(?:::.*)?$")

EVENT_WEBHOOK_MAPPING = {
    "acapy::basicmessage::received": "basicmessages",
    "acapy::problem_report": "problem_report",
    "acapy::ping::received": "ping",
    "acapy::ping::response_received": "ping",
    "acapy::actionmenu::received": "actionmenu",
    "acapy::actionmenu::get-active-menu": "get-active-menu",
    "acapy::actionmenu::perform-menu-action": "perform-menu-action",
}


class AdminModulesSchema(OpenAPISchema):
    """Schema for the modules endpoint."""

    result = fields.List(
        fields.Str(description="admin module"), description="List of admin modules"
    )


class AdminConfigSchema(OpenAPISchema):
    """Schema for the config endpoint."""

    config = fields.Dict(description="Configuration settings")


class AdminStatusSchema(OpenAPISchema):
    """Schema for the status endpoint."""

    version = fields.Str(description="Version code")
    label = fields.Str(description="Default label", allow_none=True)
    timing = fields.Dict(description="Timing results", required=False)
    conductor = fields.Dict(description="Conductor statistics", required=False)


class AdminResetSchema(OpenAPISchema):
    """Schema for the reset endpoint."""


class AdminStatusLivelinessSchema(OpenAPISchema):
    """Schema for the liveliness endpoint."""

    alive = fields.Boolean(description="Liveliness status", example=True)


class AdminStatusReadinessSchema(OpenAPISchema):
    """Schema for the readiness endpoint."""

    ready = fields.Boolean(description="Readiness status", example=True)


class AdminShutdownSchema(OpenAPISchema):
    """Response schema for admin Module."""


class AdminResponder(BaseResponder):
    """Handle outgoing messages from message handlers."""

    def __init__(
        self,
        profile: Profile,
        send: Coroutine,
        **kwargs,
    ):
        """
        Initialize an instance of `AdminResponder`.

        Args:
            send: Function to send outbound message

        """
        super().__init__(**kwargs)
        self._profile = profile
        self._send = send

    async def send_outbound(self, message: OutboundMessage) -> OutboundSendStatus:
        """
        Send outbound message.

        Args:
            message: The `OutboundMessage` to be sent
        """
        return await self._send(self._profile, message)

    async def send_webhook(self, topic: str, payload: dict):
        """
        Dispatch a webhook. DEPRECATED: use the event bus instead.

        Args:
            topic: the webhook topic identifier
            payload: the webhook payload value
        """
        warnings.warn(
            "responder.send_webhook is deprecated; please use the event bus instead.",
            DeprecationWarning,
        )
        await self._profile.notify("acapy::webhook::" + topic, payload)

    @property
    def send_fn(self) -> Coroutine:
        """Accessor for async function to send outbound message."""
        return self._send


@web.middleware
async def ready_middleware(request: web.BaseRequest, handler: Coroutine):
    """Only continue if application is ready to take work."""

    if (
        str(request.rel_url).rstrip("/")
        in (
            "/status/live",
            "/status/ready",
        )
        or request.app._state.get("ready")
    ):
        try:
            return await handler(request)
        except (LedgerConfigError, LedgerTransactionError) as e:
            # fatal, signal server shutdown
            LOGGER.error("Shutdown with %s", str(e))
            request.app._state["ready"] = False
            request.app._state["alive"] = False
            raise
        except web.HTTPFound as e:
            # redirect, typically / -> /api/doc
            LOGGER.info("Handler redirect to: %s", e.location)
            raise
        except asyncio.CancelledError:
            # redirection spawns new task and cancels old
            LOGGER.debug("Task cancelled")
            raise
        except Exception as e:
            # some other error?
            LOGGER.error("Handler error with exception: %s", str(e))
            import traceback

            print("\n=================")
            traceback.print_exc()
            raise

    raise web.HTTPServiceUnavailable(reason="Shutdown in progress")


@web.middleware
async def debug_middleware(request: web.BaseRequest, handler: Coroutine):
    """Show request detail in debug log."""

    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug(f"Incoming request: {request.method} {request.path_qs}")
        LOGGER.debug(f"Match info: {request.match_info}")
        body = await request.text() if request.body_exists else None
        LOGGER.debug(f"Body: {body}")

    return await handler(request)


def const_compare(string1, string2):
    """Compare two strings in constant time."""
    if string1 is None or string2 is None:
        return False
    return compare_digest(string1.encode(), string2.encode())


class AdminServer(BaseAdminServer):
    """Admin HTTP server class."""

    def __init__(
        self,
        host: str,
        port: int,
        context: InjectionContext,
        root_profile: Profile,
        outbound_message_router: Coroutine,
        webhook_router: Callable,
        conductor_stop: Coroutine,
        task_queue: TaskQueue = None,
        conductor_stats: Coroutine = None,
    ):
        """
        Initialize an AdminServer instance.

        Args:
            host: Host to listen on
            port: Port to listen on
            context: The application context instance
            outbound_message_router: Coroutine for delivering outbound messages
            webhook_router: Callable for delivering webhooks
            conductor_stop: Conductor (graceful) stop for shutdown API call
            task_queue: An optional task queue for handlers
            conductor_stats: Conductor statistics API call
        """
        self.app = None
        self.admin_api_key = context.settings.get("admin.admin_api_key")
        self.admin_insecure_mode = bool(
            context.settings.get("admin.admin_insecure_mode")
        )
        self.host = host
        self.port = port
        self.context = context
        self.conductor_stop = conductor_stop
        self.conductor_stats = conductor_stats
        self.loaded_modules = []
        self.outbound_message_router = outbound_message_router
        self.root_profile = root_profile
        self.task_queue = task_queue
        self.webhook_router = webhook_router
        self.websocket_queues = {}
        self.site = None
        self.multitenant_manager = context.inject(MultitenantManager, required=False)

        self.server_paths = []

    async def make_application(self) -> web.Application:
        """Get the aiohttp application instance."""

        middlewares = [ready_middleware, debug_middleware, validation_middleware]

        # admin-token and admin-token are mutually exclusive and required.
        # This should be enforced during parameter parsing but to be sure,
        # we check here.
        assert self.admin_insecure_mode ^ bool(self.admin_api_key)

        def is_unprotected_path(path: str):
            return (
                path
                in [
                    "/api/doc",
                    "/api/docs/swagger.json",
                    "/favicon.ico",
                    "/.well-known/did.json"
                    "/ws",  # ws handler checks authentication
                ]
                or path.startswith("/static/swagger/")
            )

        # If admin_api_key is None, then admin_insecure_mode must be set so
        # we can safely enable the admin server with no security
        if self.admin_api_key:

            @web.middleware
            async def check_token(request: web.Request, handler):
                header_admin_api_key = request.headers.get("x-api-key")
                valid_key = const_compare(self.admin_api_key, header_admin_api_key)

                if valid_key or is_unprotected_path(request.path):
                    return await handler(request)
                else:
                    raise web.HTTPUnauthorized()

            middlewares.append(check_token)

        collector = self.context.inject(Collector, required=False)

        if self.multitenant_manager:

            @web.middleware
            async def check_multitenant_authorization(request: web.Request, handler):
                authorization_header = request.headers.get("Authorization")
                path = request.path

                is_multitenancy_path = path.startswith("/multitenancy")
                is_server_path = path in self.server_paths or path == "/features"

                # subwallets are not allowed to access multitenancy routes
                if authorization_header and is_multitenancy_path:
                    raise web.HTTPUnauthorized()

                # base wallet is not allowed to perform ssi related actions.
                # Only multitenancy and general server actions
                if (
                    not authorization_header
                    and not is_multitenancy_path
                    and not is_server_path
                    and not is_unprotected_path(path)
                ):
                    raise web.HTTPUnauthorized()

                return await handler(request)

            middlewares.append(check_multitenant_authorization)

        @web.middleware
        async def setup_context(request: web.Request, handler):
            authorization_header = request.headers.get("Authorization")
            profile = self.root_profile

            # Multitenancy context setup
            if self.multitenant_manager and authorization_header:
                try:
                    bearer, _, token = authorization_header.partition(" ")
                    if bearer != "Bearer":
                        raise web.HTTPUnauthorized(
                            reason="Invalid Authorization header structure"
                        )

                    profile = await self.multitenant_manager.get_profile_for_token(
                        self.context, token
                    )
                except MultitenantManagerError as err:
                    raise web.HTTPUnauthorized(reason=err.roll_up)
                except (jwt.InvalidTokenError, StorageNotFoundError):
                    raise web.HTTPUnauthorized()

            # Create a responder with the request specific context
            responder = AdminResponder(
                profile,
                self.outbound_message_router,
            )
            profile.context.injector.bind_instance(BaseResponder, responder)

            # TODO may dynamically adjust the profile used here according to
            # headers or other parameters
            admin_context = AdminRequestContext(profile)

            request["context"] = admin_context
            request["outbound_message_router"] = responder.send

            if collector:
                handler = collector.wrap_coro(handler, [handler.__qualname__])
            if self.task_queue:
                task = await self.task_queue.put(handler(request))
                return await task
            return await handler(request)

        middlewares.append(setup_context)

        app = web.Application(
            middlewares=middlewares,
            client_max_size=(
                self.context.settings.get("admin.admin_client_max_request_size", 1)
                * 1024
                * 1024
            ),
        )

        server_routes = [
            web.get("/", self.redirect_handler, allow_head=False),
            web.get("/plugins", self.plugins_handler, allow_head=False),
            web.get("/status", self.status_handler, allow_head=False),
            web.get("/status/config", self.config_handler, allow_head=False),
            web.post("/status/reset", self.status_reset_handler),
            web.get("/status/live", self.liveliness_handler, allow_head=False),
            web.get("/status/ready", self.readiness_handler, allow_head=False),
            web.get("/shutdown", self.shutdown_handler, allow_head=False),
            web.get("/ws", self.websocket_handler, allow_head=False),
        ]

        # Store server_paths for multitenant authorization handling
        self.server_paths = [route.path for route in server_routes]
        app.add_routes(server_routes)

        plugin_registry = self.context.inject(PluginRegistry, required=False)
        if plugin_registry:
            await plugin_registry.register_admin_routes(app)

        cors = aiohttp_cors.setup(
            app,
            defaults={
                "*": aiohttp_cors.ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*",
                )
            },
        )
        for route in app.router.routes():
            cors.add(route)
        # get agent label
        agent_label = self.context.settings.get("default_label")
        version_string = f"v{__version__}"

        setup_aiohttp_apispec(
            app=app, title=agent_label, version=version_string, swagger_path="/api/doc"
        )
        app.on_startup.append(self.on_startup)

        # ensure we always have status values
        app._state["ready"] = False
        app._state["alive"] = False

        return app

    async def start(self) -> None:
        """
        Start the webserver.

        Raises:
            AdminSetupError: If there was an error starting the webserver

        """

        def sort_dict(raw: dict) -> dict:
            """Order (JSON, string keys) dict asciibetically by key, recursively."""
            for (k, v) in raw.items():
                if isinstance(v, dict):
                    raw[k] = sort_dict(v)
            return dict(sorted([item for item in raw.items()], key=lambda x: x[0]))

        self.app = await self.make_application()
        runner = web.AppRunner(self.app)
        await runner.setup()

        plugin_registry = self.context.inject(PluginRegistry, required=False)
        if plugin_registry:
            plugin_registry.post_process_routes(self.app)

        event_bus = self.context.inject(EventBus, required=False)
        if event_bus:
            event_bus.subscribe(EVENT_PATTERN_WEBHOOK, self._on_webhook_event)
            event_bus.subscribe(EVENT_PATTERN_RECORD, self._on_record_event)

            for event_topic, webhook_topic in EVENT_WEBHOOK_MAPPING.items():
                event_bus.subscribe(
                    re.compile(re.escape(event_topic)),
                    lambda profile, event, webhook_topic=webhook_topic: self.send_webhook(
                        profile, webhook_topic, event.payload
                    ),
                )

        # order tags alphabetically, parameters deterministically and pythonically
        swagger_dict = self.app._state["swagger_dict"]
        swagger_dict.get("tags", []).sort(key=lambda t: t["name"])

        # sort content per path and sort paths
        for path_spec in swagger_dict["paths"].values():
            for method_spec in path_spec.values():
                method_spec["parameters"].sort(
                    key=lambda p: (p["in"], not p["required"], p["name"])
                )
        for path in sorted([p for p in swagger_dict["paths"]]):
            swagger_dict["paths"][path] = swagger_dict["paths"].pop(path)

        # order definitions alphabetically by dict key
        swagger_dict["definitions"] = sort_dict(swagger_dict["definitions"])

        self.site = web.TCPSite(runner, host=self.host, port=self.port)

        try:
            await self.site.start()
            self.app._state["ready"] = True
            self.app._state["alive"] = True
        except OSError:
            raise AdminSetupError(
                "Unable to start webserver with host "
                + f"'{self.host}' and port '{self.port}'\n"
            )

    async def stop(self) -> None:
        """Stop the webserver."""
        self.app._state["ready"] = False  # in case call does not come through OpenAPI
        for queue in self.websocket_queues.values():
            queue.stop()
        if self.site:
            await self.site.stop()
            self.site = None

    async def on_startup(self, app: web.Application):
        """Perform webserver startup actions."""
        security_definitions = {}
        security = []

        if self.admin_api_key:
            security_definitions["ApiKeyHeader"] = {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-KEY",
            }
            security.append({"ApiKeyHeader": []})
        if self.multitenant_manager:
            security_definitions["AuthorizationHeader"] = {
                "type": "apiKey",
                "in": "header",
                "name": "Authorization",
                "description": "Bearer token. Be sure to preprend token with 'Bearer '",
            }

            # If multitenancy is enabled we need Authorization header
            multitenant_security = {"AuthorizationHeader": []}
            # If admin api key is also enabled, we need both for subwallet requests
            if self.admin_api_key:
                multitenant_security["ApiKeyHeader"] = []
            security.append(multitenant_security)

        if self.admin_api_key or self.multitenant_manager:
            swagger = app["swagger_dict"]
            swagger["securityDefinitions"] = security_definitions
            swagger["security"] = security

    @docs(tags=["server"], summary="Fetch the list of loaded plugins")
    @response_schema(AdminModulesSchema(), 200, description="")
    async def plugins_handler(self, request: web.BaseRequest):
        """
        Request handler for the loaded plugins list.

        Args:
            request: aiohttp request object

        Returns:
            The module list response

        """
        registry = self.context.inject(PluginRegistry, required=False)
        plugins = registry and sorted(registry.plugin_names) or []
        return web.json_response({"result": plugins})

    @docs(tags=["server"], summary="Fetch the server configuration")
    @response_schema(AdminConfigSchema(), 200, description="")
    async def config_handler(self, request: web.BaseRequest):
        """
        Request handler for the server configuration.

        Args:
            request: aiohttp request object

        Returns:
            The web response

        """
        config = {
            k: self.context.settings[k]
            for k in self.context.settings
            if k
            not in [
                "admin.admin_api_key",
                "multitenant.jwt_secret",
                "wallet.key",
                "wallet.rekey",
                "wallet.seed",
                "wallet.storage.creds",
            ]
        }
        for index in range(len(config.get("admin.webhook_urls", []))):
            config["admin.webhook_urls"][index] = re.sub(
                r"#.*",
                "",
                config["admin.webhook_urls"][index],
            )

        return web.json_response({"config": config})

    @docs(tags=["server"], summary="Fetch the server status")
    @response_schema(AdminStatusSchema(), 200, description="")
    async def status_handler(self, request: web.BaseRequest):
        """
        Request handler for the server status information.

        Args:
            request: aiohttp request object

        Returns:
            The web response

        """
        status = {"version": __version__}
        status["label"] = self.context.settings.get("default_label")
        collector = self.context.inject(Collector, required=False)
        if collector:
            status["timing"] = collector.results
        if self.conductor_stats:
            status["conductor"] = await self.conductor_stats()
        return web.json_response(status)

    @docs(tags=["server"], summary="Reset statistics")
    @response_schema(AdminResetSchema(), 200, description="")
    async def status_reset_handler(self, request: web.BaseRequest):
        """
        Request handler for resetting the timing statistics.

        Args:
            request: aiohttp request object

        Returns:
            The web response

        """
        collector = self.context.inject(Collector, required=False)
        if collector:
            collector.reset()
        return web.json_response({})

    async def redirect_handler(self, request: web.BaseRequest):
        """Perform redirect to documentation."""
        raise web.HTTPFound("/api/doc")

    @docs(tags=["server"], summary="Liveliness check")
    @response_schema(AdminStatusLivelinessSchema(), 200, description="")
    async def liveliness_handler(self, request: web.BaseRequest):
        """
        Request handler for liveliness check.

        Args:
            request: aiohttp request object

        Returns:
            The web response, always indicating True

        """
        app_live = self.app._state["alive"]
        if app_live:
            return web.json_response({"alive": app_live})
        else:
            raise web.HTTPServiceUnavailable(reason="Service not available")

    @docs(tags=["server"], summary="Readiness check")
    @response_schema(AdminStatusReadinessSchema(), 200, description="")
    async def readiness_handler(self, request: web.BaseRequest):
        """
        Request handler for liveliness check.

        Args:
            request: aiohttp request object

        Returns:
            The web response, indicating readiness for further calls

        """
        app_ready = self.app._state["ready"] and self.app._state["alive"]
        if app_ready:
            return web.json_response({"ready": app_ready})
        else:
            raise web.HTTPServiceUnavailable(reason="Service not ready")

    @docs(tags=["server"], summary="Shut down server")
    @response_schema(AdminShutdownSchema(), description="")
    async def shutdown_handler(self, request: web.BaseRequest):
        """
        Request handler for server shutdown.

        Args:
            request: aiohttp request object

        Returns:
            The web response (empty production)

        """
        self.app._state["ready"] = False
        loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.conductor_stop(), loop=loop)

        return web.json_response({})

    def notify_fatal_error(self):
        """Set our readiness flags to force a restart (openshift)."""
        LOGGER.error("Received shutdown request notify_fatal_error()")
        self.app._state["ready"] = False
        self.app._state["alive"] = False

    async def websocket_handler(self, request):
        """Send notifications to admin client over websocket."""

        ws = web.WebSocketResponse()
        await ws.prepare(request)
        socket_id = str(uuid.uuid4())
        queue = BasicMessageQueue()
        loop = asyncio.get_event_loop()

        if self.admin_insecure_mode:
            # open to send websocket messages without api key auth
            queue.authenticated = True
        else:
            header_admin_api_key = request.headers.get("x-api-key")
            # authenticated via http header?
            queue.authenticated = const_compare(
                header_admin_api_key, self.admin_api_key
            )

        try:
            self.websocket_queues[socket_id] = queue
            await queue.enqueue(
                {
                    "topic": "settings",
                    "payload": {
                        "authenticated": queue.authenticated,
                        "label": self.context.settings.get("default_label"),
                        "endpoint": self.context.settings.get("default_endpoint"),
                        "no_receive_invites": self.context.settings.get(
                            "admin.no_receive_invites", False
                        ),
                        "help_link": self.context.settings.get("admin.help_link"),
                    },
                }
            )

            closed = False
            receive = loop.create_task(ws.receive_json())
            send = loop.create_task(queue.dequeue(timeout=5.0))

            while not closed:
                try:
                    await asyncio.wait(
                        (receive, send), return_when=asyncio.FIRST_COMPLETED
                    )
                    if ws.closed:
                        closed = True

                    if receive.done():
                        if not closed:
                            msg_received = None
                            msg_api_key = None
                            try:
                                # this call can re-raise exeptions from inside the task
                                msg_received = receive.result()
                                msg_api_key = msg_received.get("x-api-key")
                            except Exception:
                                LOGGER.exception(
                                    "Exception in websocket receiving task:"
                                )
                            if self.admin_api_key and const_compare(
                                self.admin_api_key, msg_api_key
                            ):
                                # authenticated via websocket message
                                queue.authenticated = True

                            receive = loop.create_task(ws.receive_json())

                    if send.done():
                        try:
                            msg = send.result()
                        except asyncio.TimeoutError:
                            msg = None

                        if msg is None:
                            # we send fake pings because the JS client
                            # can't detect real ones
                            msg = {
                                "topic": "ping",
                                "authenticated": queue.authenticated,
                            }
                        if not closed:
                            if msg:
                                await ws.send_json(msg)
                            send = loop.create_task(queue.dequeue(timeout=5.0))

                except asyncio.CancelledError:
                    closed = True

            if not receive.done():
                receive.cancel()
            if not send.done():
                send.cancel()

        finally:
            del self.websocket_queues[socket_id]

        return ws

    async def _on_webhook_event(self, profile: Profile, event: Event):
        match = EVENT_PATTERN_WEBHOOK.search(event.topic)
        webhook_topic = match.group(1) if match else None
        if webhook_topic:
            await self.send_webhook(profile, webhook_topic, event.payload)

    async def _on_record_event(self, profile: Profile, event: Event):
        match = EVENT_PATTERN_RECORD.search(event.topic)
        webhook_topic = match.group(1) if match else None
        if webhook_topic:
            await self.send_webhook(profile, webhook_topic, event.payload)

    async def send_webhook(self, profile: Profile, topic: str, payload: dict = None):
        """Add a webhook to the queue, to send to all registered targets."""
        wallet_id = profile.settings.get("wallet.id")
        webhook_urls = profile.settings.get("admin.webhook_urls")

        metadata = None
        if wallet_id:
            metadata = {"x-wallet-id": wallet_id}

        if self.webhook_router:
            for endpoint in webhook_urls:
                self.webhook_router(
                    topic,
                    payload,
                    endpoint,
                    None,
                    metadata,
                )

        # set ws webhook body, optionally add wallet id for multitenant mode
        webhook_body = {"topic": topic, "payload": payload}
        if wallet_id:
            webhook_body["wallet_id"] = wallet_id

        for queue in self.websocket_queues.values():
            if queue.authenticated or topic in ("ping", "settings"):
                await queue.enqueue(webhook_body)
