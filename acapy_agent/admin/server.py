"""Admin server classes."""

import asyncio
import logging
import re
import warnings
import weakref
from typing import Callable, Coroutine, Optional

import aiohttp_cors
import jwt
from aiohttp import web
from aiohttp_apispec import setup_aiohttp_apispec, validation_middleware
from uuid_utils import uuid4

from ..config.injection_context import InjectionContext
from ..config.logging import context_wallet_id
from ..core.event_bus import Event, EventBus
from ..core.plugin_registry import PluginRegistry
from ..core.profile import Profile
from ..ledger.error import LedgerConfigError, LedgerTransactionError
from ..messaging.responder import BaseResponder
from ..multitenant.base import BaseMultitenantManager
from ..multitenant.error import InvalidTokenError, MultitenantManagerError
from ..storage.base import BaseStorage
from ..storage.error import StorageNotFoundError
from ..storage.type import RECORD_TYPE_ACAPY_UPGRADING
from ..transport.outbound.message import OutboundMessage
from ..transport.outbound.status import OutboundSendStatus
from ..transport.queue.basic import BasicMessageQueue
from ..utils import general as general_utils
from ..utils.extract_validation_error import extract_validation_error_message
from ..utils.stats import Collector
from ..utils.task_queue import TaskQueue
from ..version import __version__
from ..wallet import singletons
from ..wallet.anoncreds_upgrade import check_upgrade_completion_loop
from .base_server import BaseAdminServer
from .error import AdminSetupError
from .request_context import AdminRequestContext
from .routes import (
    config_handler,
    liveliness_handler,
    plugins_handler,
    readiness_handler,
    redirect_handler,
    shutdown_handler,
    status_handler,
    status_reset_handler,
)

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
    "acapy::keylist::updated": "keylist",
}

anoncreds_wallets = singletons.IsAnoncredsSingleton().wallets
in_progress_upgrades = singletons.UpgradeInProgressSingleton()

status_paths = ("/status/live", "/status/ready")


class AdminResponder(BaseResponder):
    """Handle outgoing messages from message handlers."""

    def __init__(
        self,
        profile: Profile,
        send: Coroutine,
        **kwargs,
    ):
        """Initialize an instance of `AdminResponder`.

        Args:
            profile (Profile): The profile for this responder.
            send (Coroutine): Function to send outbound message.
            **kwargs: Additional keyword arguments.

        """
        super().__init__(**kwargs)
        # Weakly hold the profile so this reference doesn't prevent profiles
        # from being cleaned up when appropriate.
        # Binding this AdminResponder to the profile's context creates a circular
        # reference.
        self._profile = weakref.ref(profile)
        self._send = send

    async def send_outbound(
        self, message: OutboundMessage, **kwargs
    ) -> OutboundSendStatus:
        """Send outbound message.

        Args:
            message: The `OutboundMessage` to be sent
            **kwargs: Additional keyword arguments
        """
        profile = self._profile()
        if not profile:
            raise RuntimeError("weakref to profile has expired")
        return await self._send(profile, message)

    async def send_webhook(self, topic: str, payload: dict):
        """Dispatch a webhook. DEPRECATED: use the event bus instead.

        Args:
            topic: the webhook topic identifier
            payload: the webhook payload value
        """
        warnings.warn(
            "responder.send_webhook is deprecated; please use the event bus instead.",
            DeprecationWarning,
        )
        profile = self._profile()
        if not profile:
            raise RuntimeError("weakref to profile has expired")
        await profile.notify("acapy::webhook::" + topic, payload)

    @property
    def send_fn(self) -> Coroutine:
        """Accessor for async function to send outbound message."""
        return self._send


@web.middleware
async def ready_middleware(request: web.BaseRequest, handler: Coroutine):
    """Only continue if application is ready to take work."""

    is_status_check = str(request.rel_url).rstrip("/") in status_paths
    is_app_ready = request.app._state.get("ready")

    if not (is_status_check or is_app_ready):
        raise web.HTTPServiceUnavailable(reason="Shutdown in progress")

    try:
        return await handler(request)
    except web.HTTPFound as e:
        # redirect, typically / -> /api/doc
        LOGGER.info("Handler redirect to: %s", e.location)
        raise
    except asyncio.CancelledError:
        # redirection spawns new task and cancels old
        LOGGER.debug("Task cancelled")
        raise
    except (web.HTTPUnauthorized, jwt.InvalidTokenError, InvalidTokenError) as e:
        LOGGER.info(
            "Unauthorized access during %s %s: %s", request.method, request.path, e
        )
        raise web.HTTPUnauthorized(reason=str(e)) from e
    except (web.HTTPBadRequest, MultitenantManagerError) as e:
        LOGGER.info("Bad request during %s %s: %s", request.method, request.path, e)
        raise web.HTTPBadRequest(reason=str(e)) from e
    except (web.HTTPNotFound, StorageNotFoundError) as e:
        LOGGER.info(
            "Not Found error occurred during %s %s: %s",
            request.method,
            request.path,
            e,
        )
        raise web.HTTPNotFound(reason=str(e)) from e
    except web.HTTPUnprocessableEntity as e:
        validation_error_message = extract_validation_error_message(e)
        LOGGER.info(
            "Unprocessable Entity occurred during %s %s: %s",
            request.method,
            request.path,
            validation_error_message,
        )
        raise web.HTTPUnprocessableEntity(reason=validation_error_message) from e
    except (LedgerConfigError, LedgerTransactionError) as e:
        # fatal, signal server shutdown
        LOGGER.critical("Shutdown with %s", str(e))
        request.app._state["ready"] = False
        request.app._state["alive"] = False
        raise
    except Exception as e:
        LOGGER.exception("Handler error with exception:", exc_info=e)
        raise


@web.middleware
async def upgrade_middleware(request: web.BaseRequest, handler: Coroutine):
    """Blocking middleware for upgrades."""
    context: AdminRequestContext = request["context"]

    # Already upgraded
    if context.profile.name in anoncreds_wallets:
        return await handler(request)

    # Upgrade in progress
    if context.profile.name in in_progress_upgrades.wallets:
        raise web.HTTPServiceUnavailable(reason="Upgrade in progress")

    # Avoid try/except in middleware with find_all_records
    upgrade_initiated = []
    async with context.profile.session() as session:
        storage = session.inject(BaseStorage)
        upgrade_initiated = await storage.find_all_records(RECORD_TYPE_ACAPY_UPGRADING)
        if upgrade_initiated:
            # If we get here, than another instance started an upgrade
            # We need to check for completion (or fail) in another process
            in_progress_upgrades.set_wallet(context.profile.name)
            is_subwallet = context.metadata and "wallet_id" in context.metadata
            asyncio.create_task(
                check_upgrade_completion_loop(
                    context.profile,
                    is_subwallet,
                )
            )
            raise web.HTTPServiceUnavailable(reason="Upgrade in progress")

    return await handler(request)


@web.middleware
async def debug_middleware(request: web.BaseRequest, handler: Coroutine):
    """Show request detail in debug log."""

    is_status_check = str(request.rel_url).startswith("/status/")

    if LOGGER.isEnabledFor(logging.DEBUG) and not is_status_check:
        LOGGER.debug(f"Incoming request: {request.method} {request.path_qs}")
        LOGGER.debug(f"Match info: {request.match_info}")

        if request.body_exists:
            body = await request.text()
            LOGGER.debug(f"Body: {body}")

    return await handler(request)


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
        task_queue: Optional[TaskQueue] = None,
        conductor_stats: Optional[Coroutine] = None,
    ):
        """Initialize an AdminServer instance.

        Args:
            host (str): The host to listen on.
            port (int): The port to listen on.
            context (InjectionContext): The application context instance.
            root_profile (Profile): The root profile.
            outbound_message_router (Coroutine): Coroutine for delivering
                outbound messages.
            webhook_router (Callable): Callable for delivering webhooks.
            conductor_stop (Coroutine): Conductor (graceful) stop for shutdown API call.
            task_queue (TaskQueue, optional): An optional task queue for handlers.
            conductor_stats (Coroutine, optional): Conductor statistics API call.
        """
        self.app = None
        self.admin_api_key = context.settings.get("admin.admin_api_key")
        self.admin_insecure_mode = bool(context.settings.get("admin.admin_insecure_mode"))
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
        self.multitenant_manager = context.inject_or(BaseMultitenantManager)

    async def make_application(self) -> web.Application:
        """Get the aiohttp application instance."""

        middlewares = [ready_middleware, debug_middleware]

        # admin-token and admin-token are mutually exclusive and required.
        # This should be enforced during parameter parsing but to be sure,
        # we check here.
        assert self.admin_insecure_mode ^ bool(self.admin_api_key)

        collector = self.context.inject_or(Collector)

        @web.middleware
        async def setup_context(request: web.Request, handler):
            authorization_header = request.headers.get("Authorization")
            profile = self.root_profile
            meta_data = {}
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
                    (
                        walletid,
                        walletkey,
                    ) = self.multitenant_manager.get_wallet_details_from_token(
                        token=token
                    )
                    wallet_id = profile.settings.get("wallet.id")
                    context_wallet_id.set(wallet_id)
                    meta_data = {
                        "wallet_id": walletid,
                        "wallet_key": walletkey,
                    }
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
            if self.multitenant_manager and authorization_header:
                admin_context = AdminRequestContext(
                    profile=profile,
                    root_profile=self.root_profile,
                    metadata=meta_data,
                )
            else:
                admin_context = AdminRequestContext(
                    profile=profile,
                )

            request["context"] = admin_context
            request["outbound_message_router"] = responder.send

            if collector:
                handler = collector.wrap_coro(handler, [handler.__qualname__])
            if self.task_queue:
                task = await self.task_queue.put(handler(request))
                return await task
            return await handler(request)

        middlewares.append(setup_context)

        # Upgrade middleware needs the context setup
        middlewares.append(upgrade_middleware)

        # Register validation_middleware last avoiding unauthorized validations
        middlewares.append(validation_middleware)

        app = web.Application(
            middlewares=middlewares,
            client_max_size=(
                self.context.settings.get("admin.admin_client_max_request_size", 1)
                * 1024
                * 1024
            ),
        )

        server_routes = [
            web.get("/", redirect_handler, allow_head=True),
            web.get("/plugins", plugins_handler, allow_head=False),
            web.get("/status", status_handler, allow_head=False),
            web.get("/status/config", config_handler, allow_head=False),
            web.post("/status/reset", status_reset_handler),
            web.get("/status/live", liveliness_handler, allow_head=False),
            web.get("/status/ready", readiness_handler, allow_head=False),
            web.get("/shutdown", shutdown_handler, allow_head=False),
            web.get("/ws", self.websocket_handler, allow_head=False),
        ]
        app.add_routes(server_routes)

        plugin_registry = self.context.inject_or(PluginRegistry)
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

        # set global-like variables
        app["context"] = self.context
        app["conductor_stats"] = self.conductor_stats
        app["conductor_stop"] = self.conductor_stop

        return app

    async def start(self) -> None:
        """Start the webserver.

        Raises:
            AdminSetupError: If there was an error starting the webserver

        """

        def sort_dict(raw: dict) -> dict:
            """Order (JSON, string keys) dict asciibetically by key, recursively."""
            for k, v in raw.items():
                if isinstance(v, dict):
                    raw[k] = sort_dict(v)
            return dict(sorted(raw.items(), key=lambda x: x[0]))

        self.app = await self.make_application()
        runner = web.AppRunner(self.app)
        await runner.setup()

        plugin_registry = self.context.inject_or(PluginRegistry)
        if plugin_registry:
            plugin_registry.post_process_routes(self.app)

        event_bus = self.context.inject_or(EventBus)
        if event_bus:
            event_bus.subscribe(EVENT_PATTERN_WEBHOOK, self._on_webhook_event)
            event_bus.subscribe(EVENT_PATTERN_RECORD, self._on_record_event)

            # Only include forward webhook events if the option is enabled
            if self.context.settings.get_bool("monitor_forward", False):
                EVENT_WEBHOOK_MAPPING["acapy::forward::received"] = "forward"

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
        for path in sorted(swagger_dict["paths"]):
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
        # Stopped before admin server is created
        if not self.app:
            return

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
                "description": "Bearer token. Be sure to prepend token with 'Bearer '",
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

    def notify_fatal_error(self):
        """Set our readiness flags to force a restart (openshift)."""
        LOGGER.error("Received shutdown request notify_fatal_error()")
        self.app._state["ready"] = False
        self.app._state["alive"] = False

    async def websocket_handler(self, request):
        """Send notifications to admin client over websocket."""

        ws = web.WebSocketResponse()
        await ws.prepare(request)
        socket_id = str(uuid4())
        queue = BasicMessageQueue()
        loop = asyncio.get_event_loop()

        if self.admin_insecure_mode:
            # open to send websocket messages without api key auth
            queue.authenticated = True
        else:
            header_admin_api_key = request.headers.get("x-api-key")
            # authenticated via http header?
            queue.authenticated = general_utils.const_compare(
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
                                # this call can re-raise exceptions from inside the task
                                msg_received = receive.result()
                                msg_api_key = msg_received.get("x-api-key")
                            except Exception:
                                LOGGER.exception("Exception in websocket receiving task:")
                            if self.admin_api_key and general_utils.const_compare(
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

    async def send_webhook(
        self, profile: Profile, topic: str, payload: Optional[dict] = None
    ):
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
