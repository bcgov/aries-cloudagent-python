"""
The Conductor.

The conductor is responsible for coordinating messages that are received
over the network, communicating with the ledger, passing messages to handlers,
instantiating concrete implementations of required modules and storing data in the
wallet.

"""

import hashlib
import json
import logging

from ..admin.base_server import BaseAdminServer
from ..admin.server import AdminResponder, AdminServer
from ..config.default_context import ContextBuilder
from ..config.injection_context import InjectionContext
from ..config.ledger import get_genesis_transactions, ledger_config
from ..config.logging import LoggingConfigurator
from ..config.wallet import wallet_config
from ..core.profile import Profile
from ..ledger.error import LedgerConfigError, LedgerTransactionError
from ..messaging.responder import BaseResponder
from ..multitenant.manager import MultitenantManager
from ..protocols.connections.v1_0.manager import (
    ConnectionManager,
    ConnectionManagerError,
)
from ..protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitation,
)
from ..protocols.coordinate_mediation.v1_0.manager import MediationManager
from ..protocols.coordinate_mediation.v1_0.models.mediation_record import (
    MediationRecord,
)
from ..protocols.out_of_band.v1_0.manager import OutOfBandManager
from ..protocols.out_of_band.v1_0.messages.invitation import InvitationMessage
from ..transport.inbound.manager import InboundTransportManager
from ..transport.inbound.message import InboundMessage
from ..transport.outbound.base import OutboundDeliveryError
from ..transport.outbound.manager import OutboundTransportManager, QueuedOutboundMessage
from ..transport.outbound.message import OutboundMessage
from ..transport.wire_format import BaseWireFormat
from ..utils.stats import Collector
from ..utils.task_queue import CompletedTask, TaskQueue
from ..wallet.base import DIDInfo
from .dispatcher import Dispatcher

LOGGER = logging.getLogger(__name__)


class Conductor:
    """
    Conductor class.

    Class responsible for initializing concrete implementations
    of our require interfaces and routing inbound and outbound message data.
    """

    def __init__(self, context_builder: ContextBuilder) -> None:
        """
        Initialize an instance of Conductor.

        Args:
            inbound_transports: Configuration for inbound transports
            outbound_transports: Configuration for outbound transports
            settings: Dictionary of various settings

        """
        self.admin_server = None
        self.context_builder = context_builder
        self.dispatcher: Dispatcher = None
        self.inbound_transport_manager: InboundTransportManager = None
        self.outbound_transport_manager: OutboundTransportManager = None
        self.root_profile: Profile = None
        self.setup_public_did: DIDInfo = None

    @property
    def context(self) -> InjectionContext:
        """Accessor for the injection context."""
        return self.root_profile.context

    async def setup(self):
        """Initialize the global request context."""

        context = await self.context_builder.build_context()

        # Fetch genesis transactions if necessary
        await get_genesis_transactions(context.settings)

        # Configure the root profile
        self.root_profile, self.setup_public_did = await wallet_config(context)
        context = self.root_profile.context

        # Configure the ledger
        if not await ledger_config(
            self.root_profile, self.setup_public_did and self.setup_public_did.did
        ):
            LOGGER.warning("No ledger configured")

        # Register all inbound transports
        self.inbound_transport_manager = InboundTransportManager(
            self.root_profile, self.inbound_message_router, self.handle_not_returned
        )
        await self.inbound_transport_manager.setup()

        # Register all outbound transports
        self.outbound_transport_manager = OutboundTransportManager(
            context, self.handle_not_delivered
        )
        await self.outbound_transport_manager.setup()

        # Initialize dispatcher
        self.dispatcher = Dispatcher(self.root_profile)
        await self.dispatcher.setup()

        wire_format = context.inject(BaseWireFormat, required=False)
        if wire_format and hasattr(wire_format, "task_queue"):
            wire_format.task_queue = self.dispatcher.task_queue

        # Bind manager for multitenancy related tasks
        if context.settings.get("multitenant.enabled"):
            multitenant_mgr = MultitenantManager(self.root_profile)
            context.injector.bind_instance(MultitenantManager, multitenant_mgr)

        # Admin API
        if context.settings.get("admin.enabled"):
            try:
                admin_host = context.settings.get("admin.host", "0.0.0.0")
                admin_port = context.settings.get("admin.port", "80")
                self.admin_server = AdminServer(
                    admin_host,
                    admin_port,
                    context,
                    self.root_profile,
                    self.outbound_message_router,
                    self.webhook_router,
                    self.stop,
                    self.dispatcher.task_queue,
                    self.get_stats,
                )
                webhook_urls = context.settings.get("admin.webhook_urls")
                if webhook_urls:
                    for url in webhook_urls:
                        self.admin_server.add_webhook_target(url)
                context.injector.bind_instance(BaseAdminServer, self.admin_server)
                if "http" not in self.outbound_transport_manager.registered_schemes:
                    self.outbound_transport_manager.register("http")
            except Exception:
                LOGGER.exception("Unable to register admin server")
                raise

        # Fetch stats collector, if any
        collector = context.inject(Collector, required=False)
        if collector:
            # add stats to our own methods
            collector.wrap(
                self,
                (
                    # "inbound_message_router",
                    "outbound_message_router",
                    # "create_inbound_session",
                ),
            )
            # at the class level (!) should not be performed multiple times
            collector.wrap(
                ConnectionManager,
                (
                    # "get_connection_targets",
                    "fetch_did_document",
                    "find_inbound_connection",
                ),
            )

    async def start(self) -> None:
        """Start the agent."""

        context = self.root_profile.context

        # Start up transports
        try:
            await self.inbound_transport_manager.start()
        except Exception:
            LOGGER.exception("Unable to start inbound transports")
            raise
        try:
            await self.outbound_transport_manager.start()
        except Exception:
            LOGGER.exception("Unable to start outbound transports")
            raise

        # Start up Admin server
        if self.admin_server:
            try:
                await self.admin_server.start()
            except Exception:
                LOGGER.exception("Unable to start administration API")
            # Make admin responder available during message parsing
            # This allows webhooks to be called when a connection is marked active,
            # for example
            responder = AdminResponder(
                self.root_profile,
                self.admin_server.outbound_message_router,
                self.admin_server.send_webhook,
            )
            context.injector.bind_instance(BaseResponder, responder)

        # Get agent label
        default_label = context.settings.get("default_label")

        # Show some details about the configuration to the user
        LoggingConfigurator.print_banner(
            default_label,
            self.inbound_transport_manager.registered_transports,
            self.outbound_transport_manager.registered_transports,
            self.setup_public_did and self.setup_public_did.did,
            self.admin_server,
        )

        # Create a static connection for use by the test-suite
        if context.settings.get("debug.test_suite_endpoint"):
            async with self.root_profile.session() as session:
                mgr = ConnectionManager(session)
                their_endpoint = context.settings["debug.test_suite_endpoint"]
                test_conn = await mgr.create_static_connection(
                    my_seed=hashlib.sha256(b"aries-protocol-test-subject").digest(),
                    their_seed=hashlib.sha256(b"aries-protocol-test-suite").digest(),
                    their_endpoint=their_endpoint,
                    alias="test-suite",
                )
                print("Created static connection for test suite")
                print(" - My DID:", test_conn.my_did)
                print(" - Their DID:", test_conn.their_did)
                print(" - Their endpoint:", their_endpoint)
                print()
                del mgr

        # Clear default mediator
        if context.settings.get("mediation.clear"):
            async with self.root_profile.session() as session:
                mediation_mgr = MediationManager(session)
                await mediation_mgr.clear_default_mediator()
                print("Default mediator cleared.")

        # Set default mediator by id
        default_mediator_id = context.settings.get("mediation.default_id")
        if default_mediator_id:
            async with self.root_profile.session() as session:
                mediation_mgr = MediationManager(session)
                try:
                    record = await MediationRecord.retrieve_by_id(
                        session, default_mediator_id
                    )
                    await mediation_mgr.set_default_mediator(record)
                    print(f"Default mediator set to {default_mediator_id}")
                except Exception:
                    LOGGER.exception("Error retrieving mediation record")

        # Print an invitation to the terminal
        if context.settings.get("debug.print_invitation"):
            try:
                async with self.root_profile.session() as session:
                    mgr = OutOfBandManager(session)
                    invi_rec = await mgr.create_invitation(
                        my_label=context.settings.get("debug.invite_label"),
                        public=context.settings.get("debug.invite_public", False),
                        multi_use=context.settings.get("debug.invite_multi_use", False),
                        include_handshake=True,
                        metadata=json.loads(
                            context.settings.get("debug.invite_metadata_json", "{}")
                        ),
                    )
                    base_url = context.settings.get("invite_base_url")
                    invite_url = InvitationMessage.deserialize(
                        invi_rec.invitation
                    ).to_url(base_url)
                    print("Invitation URL:")
                    print(invite_url, flush=True)
                    del mgr
            except Exception:
                LOGGER.exception("Error creating invitation")

        # Print connections protocol invitation to the terminal
        if context.settings.get("debug.print_connections_invitation"):
            try:
                async with self.root_profile.session() as session:
                    mgr = ConnectionManager(session)
                    _record, invite = await mgr.create_invitation(
                        my_label=context.settings.get("debug.invite_label"),
                        public=context.settings.get("debug.invite_public", False),
                        multi_use=context.settings.get("debug.invite_multi_use", False),
                        metadata=json.loads(
                            context.settings.get("debug.invite_metadata_json", "{}")
                        ),
                    )
                    base_url = context.settings.get("invite_base_url")
                    print("Invitation URL (Connections protocol):")
                    print(invite.to_url(base_url), flush=True)
                    del mgr
            except Exception:
                LOGGER.exception("Error creating invitation")

        # Accept mediation invitation if specified
        mediation_invitation = context.settings.get("mediation.invite")
        if mediation_invitation:
            try:
                async with self.root_profile.session() as session:
                    mgr = ConnectionManager(session)
                    conn_record = await mgr.receive_invitation(
                        invitation=ConnectionInvitation.from_url(mediation_invitation),
                        auto_accept=True,
                    )
                    await conn_record.metadata_set(
                        session, MediationManager.SEND_REQ_AFTER_CONNECTION, True
                    )
                    await conn_record.metadata_set(
                        session, MediationManager.SET_TO_DEFAULT_ON_GRANTED, True
                    )
                    print("Attempting to connect to mediator...")
                    del mgr
            except Exception:
                LOGGER.exception("Error accepting mediation invitation")

    async def stop(self, timeout=1.0):
        """Stop the agent."""
        shutdown = TaskQueue()
        if self.dispatcher:
            shutdown.run(self.dispatcher.complete())
        if self.admin_server:
            shutdown.run(self.admin_server.stop())
        if self.inbound_transport_manager:
            shutdown.run(self.inbound_transport_manager.stop())
        if self.outbound_transport_manager:
            shutdown.run(self.outbound_transport_manager.stop())

        # close multitenant profiles
        multitenant_mgr = self.context.inject(MultitenantManager, required=False)
        if multitenant_mgr:
            for profile in multitenant_mgr._profiles.profiles.values():
                shutdown.run(profile.close())

        if self.root_profile:
            shutdown.run(self.root_profile.close())

        await shutdown.complete(timeout)

    def inbound_message_router(
        self,
        profile: Profile,
        message: InboundMessage,
        can_respond: bool = False,
    ):
        """
        Route inbound messages.

        Args:
            context: The context associated with the inbound message
            message: The inbound message instance
            can_respond: If the session supports return routing

        """

        if message.receipt.direct_response_requested and not can_respond:
            LOGGER.warning(
                "Direct response requested, but not supported by transport: %s",
                message.transport_type,
            )

        # Note: at this point we could send the message to a shared queue
        # if this pod is too busy to process it

        try:
            self.dispatcher.queue_message(
                profile,
                message,
                self.outbound_message_router,
                self.admin_server and self.admin_server.send_webhook,
                lambda completed: self.dispatch_complete(message, completed),
            )
        except (LedgerConfigError, LedgerTransactionError) as e:
            LOGGER.error("Shutdown on ledger error %s", str(e))
            if self.admin_server:
                self.admin_server.notify_fatal_error()
            raise

    def dispatch_complete(self, message: InboundMessage, completed: CompletedTask):
        """Handle completion of message dispatch."""
        if completed.exc_info:
            LOGGER.exception(
                "Exception in message handler:", exc_info=completed.exc_info
            )
            if isinstance(completed.exc_info[1], LedgerConfigError) or isinstance(
                completed.exc_info[1], LedgerTransactionError
            ):
                LOGGER.error(
                    "%shutdown on ledger error %s",
                    "S" if self.admin_server else "No admin server to s",
                    str(completed.exc_info[1]),
                )
                if self.admin_server:
                    self.admin_server.notify_fatal_error()
            else:
                LOGGER.error(
                    "DON'T shutdown on %s %s",
                    completed.exc_info[0].__name__,
                    str(completed.exc_info[1]),
                )
        self.inbound_transport_manager.dispatch_complete(message, completed)

    async def get_stats(self) -> dict:
        """Get the current stats tracked by the conductor."""
        stats = {
            "in_sessions": len(self.inbound_transport_manager.sessions),
            "out_encode": 0,
            "out_deliver": 0,
            "task_active": self.dispatcher.task_queue.current_active,
            "task_done": self.dispatcher.task_queue.total_done,
            "task_failed": self.dispatcher.task_queue.total_failed,
            "task_pending": self.dispatcher.task_queue.current_pending,
        }
        for m in self.outbound_transport_manager.outbound_buffer:
            if m.state == QueuedOutboundMessage.STATE_ENCODE:
                stats["out_encode"] += 1
            if m.state == QueuedOutboundMessage.STATE_DELIVER:
                stats["out_deliver"] += 1
        return stats

    async def outbound_message_router(
        self,
        profile: Profile,
        outbound: OutboundMessage,
        inbound: InboundMessage = None,
    ) -> None:
        """
        Route an outbound message.

        Args:
            profile: The active profile for the request
            message: An outbound message to be sent
            inbound: The inbound message that produced this response, if available
        """
        if not outbound.target and outbound.reply_to_verkey:
            if not outbound.reply_from_verkey and inbound:
                outbound.reply_from_verkey = inbound.receipt.recipient_verkey
            # return message to an inbound session
            if self.inbound_transport_manager.return_to_session(outbound):
                return

        if not outbound.to_session_only:
            await self.queue_outbound(profile, outbound, inbound)

    def handle_not_returned(self, profile: Profile, outbound: OutboundMessage):
        """Handle a message that failed delivery via an inbound session."""
        try:
            self.dispatcher.run_task(self.queue_outbound(profile, outbound))
        except (LedgerConfigError, LedgerTransactionError) as e:
            LOGGER.error("Shutdown on ledger error %s", str(e))
            if self.admin_server:
                self.admin_server.notify_fatal_error()
            raise

    async def queue_outbound(
        self,
        profile: Profile,
        outbound: OutboundMessage,
        inbound: InboundMessage = None,
    ):
        """
        Queue an outbound message.

        Args:
            profile: The active profile
            message: An outbound message to be sent
            inbound: The inbound message that produced this response, if available
        """
        # populate connection target(s)
        if not outbound.target and not outbound.target_list and outbound.connection_id:
            async with profile.session() as session:
                conn_mgr = ConnectionManager(session)
                try:
                    outbound.target_list = await self.dispatcher.run_task(
                        conn_mgr.get_connection_targets(
                            connection_id=outbound.connection_id
                        )
                    )
                except ConnectionManagerError:
                    LOGGER.exception(
                        "Error preparing outbound message for transmission"
                    )
                    return
                except (LedgerConfigError, LedgerTransactionError) as e:
                    LOGGER.error("Shutdown on ledger error %s", str(e))
                    if self.admin_server:
                        self.admin_server.notify_fatal_error()
                    raise
                del conn_mgr

        try:
            self.outbound_transport_manager.enqueue_message(profile, outbound)
        except OutboundDeliveryError:
            LOGGER.warning("Cannot queue message for delivery, no supported transport")
            self.handle_not_delivered(profile, outbound)

    def handle_not_delivered(self, profile: Profile, outbound: OutboundMessage):
        """Handle a message that failed delivery via outbound transports."""
        self.inbound_transport_manager.return_undelivered(outbound)

    def webhook_router(
        self,
        topic: str,
        payload: dict,
        endpoint: str,
        max_attempts: int = None,
        metadata: dict = None,
    ):
        """
        Route a webhook through the outbound transport manager.

        Args:
            topic: The webhook topic
            payload: The webhook payload
            endpoint: The endpoint of the webhook target
            max_attempts: The maximum number of attempts
            metadata: Additional metadata associated with the payload
        """
        try:
            self.outbound_transport_manager.enqueue_webhook(
                topic, payload, endpoint, max_attempts, metadata
            )
        except OutboundDeliveryError:
            LOGGER.warning(
                "Cannot queue message webhook for delivery, no supported transport"
            )
