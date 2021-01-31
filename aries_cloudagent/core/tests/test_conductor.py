from io import StringIO
from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from ...admin.base_server import BaseAdminServer
from ...config.base_context import ContextBuilder
from ...config.injection_context import InjectionContext
from ...connections.models.connection_target import ConnectionTarget
from ...connections.models.diddoc import (
    DIDDoc,
    PublicKey,
    PublicKeyType,
    Service,
)
from ...core.in_memory import InMemoryProfileManager
from ...core.profile import ProfileManager
from ...core.protocol_registry import ProtocolRegistry
from ...multitenant.manager import MultitenantManager
from ...transport.inbound.message import InboundMessage
from ...transport.inbound.receipt import MessageReceipt
from ...transport.outbound.base import OutboundDeliveryError
from ...transport.outbound.manager import QueuedOutboundMessage
from ...transport.outbound.message import OutboundMessage
from ...transport.wire_format import BaseWireFormat
from ...transport.pack_format import PackWireFormat
from ...utils.stats import Collector
from ...wallet.base import BaseWallet

from .. import conductor as test_module


class Config:
    test_settings = {"admin.webhook_urls": ["http://sample.webhook.ca"]}
    test_settings_admin = {
        "admin.webhook_urls": ["http://sample.webhook.ca"],
        "admin.enabled": True,
    }
    test_settings_with_queue = {"queue.enable_undelivered_queue": True}


class TestDIDs:
    test_seed = "testseed000000000000000000000001"
    test_did = "55GkHamhTU1ZbTbV2ab9DE"
    test_verkey = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    test_endpoint = "http://localhost"

    test_target_did = "GbuDUYXaUZRfHD2jeDuQuP"
    test_target_verkey = "9WCgWKUaAJj3VWxxtzvvMQN3AoFxoBtBDo9ntwJnVVCC"

    def make_did_doc(self, did, verkey):
        doc = DIDDoc(did=did)
        controller = did
        ident = "1"
        pk_value = verkey
        pk = PublicKey(
            did, ident, pk_value, PublicKeyType.ED25519_SIG_2018, controller, False
        )
        doc.set(pk)
        recip_keys = [pk]
        router_keys = []
        service = Service(
            did, "indy", "IndyAgent", recip_keys, router_keys, self.test_endpoint
        )
        doc.set(service)
        return doc, pk


class StubContextBuilder(ContextBuilder):
    def __init__(self, settings):
        super().__init__(settings)
        self.wire_format = async_mock.create_autospec(PackWireFormat())

    async def build_context(self) -> InjectionContext:
        context = InjectionContext(settings=self.settings, enforce_typing=False)
        context.injector.bind_instance(ProfileManager, InMemoryProfileManager())
        context.injector.bind_instance(ProtocolRegistry, ProtocolRegistry())
        context.injector.bind_instance(BaseWireFormat, self.wire_format)
        return context


class StubCollectorContextBuilder(StubContextBuilder):
    async def build_context(self) -> InjectionContext:
        context = await super().build_context()
        context.injector.bind_instance(Collector, Collector())
        return context


class TestConductor(AsyncTestCase, Config, TestDIDs):
    async def test_startup(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "InboundTransportManager", autospec=True
        ) as mock_inbound_mgr, async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr, async_mock.patch.object(
            test_module, "LoggingConfigurator", autospec=True
        ) as mock_logger:

            await conductor.setup()

            session = await conductor.root_profile.session()

            wallet = session.inject(BaseWallet)
            await wallet.create_public_did()

            mock_inbound_mgr.return_value.setup.assert_awaited_once()
            mock_outbound_mgr.return_value.setup.assert_awaited_once()

            mock_inbound_mgr.return_value.registered_transports = {}
            mock_outbound_mgr.return_value.registered_transports = {}

            await conductor.start()

            mock_inbound_mgr.return_value.start.assert_awaited_once_with()
            mock_outbound_mgr.return_value.start.assert_awaited_once_with()

            mock_logger.print_banner.assert_called_once()

            await conductor.stop()

            mock_inbound_mgr.return_value.stop.assert_awaited_once_with()
            mock_outbound_mgr.return_value.stop.assert_awaited_once_with()

    async def test_startup_no_public_did(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "InboundTransportManager", autospec=True
        ) as mock_inbound_mgr, async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr, async_mock.patch.object(
            test_module, "LoggingConfigurator", autospec=True
        ) as mock_logger:

            await conductor.setup()

            mock_inbound_mgr.return_value.setup.assert_awaited_once()
            mock_outbound_mgr.return_value.setup.assert_awaited_once()

            mock_inbound_mgr.return_value.registered_transports = {}
            mock_outbound_mgr.return_value.registered_transports = {}

            # Doesn't raise
            await conductor.start()

            mock_inbound_mgr.return_value.start.assert_awaited_once_with()
            mock_outbound_mgr.return_value.start.assert_awaited_once_with()

            mock_logger.print_banner.assert_called_once()

            await conductor.stop()

            mock_inbound_mgr.return_value.stop.assert_awaited_once_with()
            mock_outbound_mgr.return_value.stop.assert_awaited_once_with()

    async def test_stats(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "InboundTransportManager", autospec=True
        ) as mock_inbound_mgr, async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr, async_mock.patch.object(
            test_module, "LoggingConfigurator", autospec=True
        ) as mock_logger:

            mock_inbound_mgr.return_value.sessions = ["dummy"]
            mock_outbound_mgr.return_value.outbound_buffer = [
                async_mock.MagicMock(state=QueuedOutboundMessage.STATE_ENCODE),
                async_mock.MagicMock(state=QueuedOutboundMessage.STATE_DELIVER),
            ]

            await conductor.setup()

            stats = await conductor.get_stats()
            assert all(
                x in stats
                for x in [
                    "in_sessions",
                    "out_encode",
                    "out_deliver",
                    "task_active",
                    "task_done",
                    "task_failed",
                    "task_pending",
                ]
            )

    async def test_setup_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings(
            {"admin.enabled": "1", "admin.webhook_urls": ["http://sample.webhook.ca"]}
        )
        conductor = test_module.Conductor(builder)

        mock_om = async_mock.MagicMock(
            setup=async_mock.CoroutineMock(),
            register=async_mock.MagicMock(side_effect=KeyError("sample error")),
            registered_schemes={},
        )
        with async_mock.patch.object(
            test_module, "InboundTransportManager", autospec=True
        ) as mock_inbound_mgr, async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr, async_mock.patch.object(
            test_module, "LoggingConfigurator", async_mock.MagicMock()
        ) as mock_logger:
            mock_outbound_mgr.return_value = mock_om

            with self.assertRaises(KeyError):
                await conductor.setup()

    async def test_inbound_message_handler(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            conductor.dispatcher, "queue_message", autospec=True
        ) as mock_dispatch_q:

            message_body = "{}"
            receipt = MessageReceipt(direct_response_mode="snail mail")
            message = InboundMessage(message_body, receipt)

            conductor.inbound_message_router(
                conductor.context, message, can_respond=False
            )

            mock_dispatch_q.assert_called_once()
            assert mock_dispatch_q.call_args[0][0] is conductor.context
            assert mock_dispatch_q.call_args[0][1] is message
            assert mock_dispatch_q.call_args[0][2] == conductor.outbound_message_router
            assert mock_dispatch_q.call_args[0][3] is None  # admin webhook router
            assert callable(mock_dispatch_q.call_args[0][4])

    async def test_inbound_message_handler_ledger_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings_admin)
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            conductor.dispatcher, "queue_message", autospec=True
        ) as mock_dispatch_q, async_mock.patch.object(
            conductor.admin_server, "notify_fatal_error", async_mock.MagicMock()
        ) as mock_notify:
            mock_dispatch_q.side_effect = test_module.LedgerConfigError("ledger down")

            message_body = "{}"
            receipt = MessageReceipt(direct_response_mode="snail mail")
            message = InboundMessage(message_body, receipt)

            with self.assertRaises(test_module.LedgerConfigError):
                conductor.inbound_message_router(
                    conductor.context, message, can_respond=False
                )

            mock_dispatch_q.assert_called_once()
            mock_notify.assert_called_once()

    async def test_outbound_message_handler_return_route(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)
        test_to_verkey = "test-to-verkey"
        test_from_verkey = "test-from-verkey"

        await conductor.setup()

        payload = "{}"
        message = OutboundMessage(payload=payload)
        message.reply_to_verkey = test_to_verkey
        receipt = MessageReceipt()
        receipt.recipient_verkey = test_from_verkey
        inbound = InboundMessage("[]", receipt)

        with async_mock.patch.object(
            conductor.inbound_transport_manager, "return_to_session"
        ) as mock_return, async_mock.patch.object(
            conductor, "queue_outbound", async_mock.CoroutineMock()
        ) as mock_queue:
            mock_return.return_value = True
            await conductor.outbound_message_router(conductor.context, message)
            mock_return.assert_called_once_with(message)
            mock_queue.assert_not_awaited()

    async def test_outbound_message_handler_with_target(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr:

            await conductor.setup()

            payload = "{}"
            target = ConnectionTarget(
                endpoint="endpoint", recipient_keys=(), routing_keys=(), sender_key=""
            )
            message = OutboundMessage(payload=payload, target=target)

            await conductor.outbound_message_router(conductor.context, message)

            mock_outbound_mgr.return_value.enqueue_message.assert_called_once_with(
                conductor.context, message
            )

    async def test_outbound_message_handler_with_connection(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr, async_mock.patch.object(
            test_module, "ConnectionManager", autospec=True
        ) as conn_mgr:

            await conductor.setup()

            payload = "{}"
            connection_id = "connection_id"
            message = OutboundMessage(payload=payload, connection_id=connection_id)

            await conductor.outbound_message_router(conductor.root_profile, message)

            conn_mgr.return_value.get_connection_targets.assert_awaited_once_with(
                connection_id=connection_id
            )
            assert (
                message.target_list
                is conn_mgr.return_value.get_connection_targets.return_value
            )

            mock_outbound_mgr.return_value.enqueue_message.assert_called_once_with(
                conductor.root_profile, message
            )

    async def test_outbound_message_handler_with_verkey_no_target(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr:

            await conductor.setup()

            payload = "{}"
            message = OutboundMessage(
                payload=payload, reply_to_verkey=TestDIDs.test_verkey
            )

            await conductor.outbound_message_router(
                conductor.context,
                message,
                inbound=async_mock.MagicMock(
                    receipt=async_mock.MagicMock(recipient_verkey=TestDIDs.test_verkey)
                ),
            )

            mock_outbound_mgr.return_value.enqueue_message.assert_called_once_with(
                conductor.context, message
            )

    async def test_handle_nots(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "OutboundTransportManager", async_mock.MagicMock()
        ) as mock_outbound_mgr:
            mock_outbound_mgr.return_value = async_mock.MagicMock(
                setup=async_mock.CoroutineMock(),
                enqueue_message=async_mock.MagicMock(),
            )

            payload = "{}"
            message = OutboundMessage(
                payload=payload,
                connection_id="dummy-conn-id",
                reply_to_verkey=TestDIDs.test_verkey,
            )

            await conductor.setup()

            conductor.handle_not_returned(conductor.root_profile, message)

            with async_mock.patch.object(
                test_module, "ConnectionManager"
            ) as mock_conn_mgr, async_mock.patch.object(
                conductor.dispatcher, "run_task", async_mock.MagicMock()
            ) as mock_run_task:
                mock_conn_mgr.return_value.get_connection_targets = (
                    async_mock.CoroutineMock()
                )
                mock_run_task.side_effect = test_module.ConnectionManagerError()
                await conductor.queue_outbound(conductor.root_profile, message)
                mock_outbound_mgr.return_value.enqueue_message.assert_not_called()

                message.connection_id = None
                mock_outbound_mgr.return_value.enqueue_message.side_effect = (
                    test_module.OutboundDeliveryError()
                )
                await conductor.queue_outbound(conductor.root_profile, message)
                mock_run_task.assert_called_once()

    async def test_handle_not_returned_ledger_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings_admin)
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            conductor.dispatcher, "run_task", async_mock.MagicMock()
        ) as mock_dispatch_run, async_mock.patch.object(
            conductor, "queue_outbound", async_mock.CoroutineMock()
        ) as mock_queue, async_mock.patch.object(
            conductor.admin_server, "notify_fatal_error", async_mock.MagicMock()
        ) as mock_notify:
            mock_dispatch_run.side_effect = test_module.LedgerConfigError(
                "No such ledger"
            )

            payload = "{}"
            message = OutboundMessage(
                payload=payload,
                connection_id="dummy-conn-id",
                reply_to_verkey=TestDIDs.test_verkey,
            )

            with self.assertRaises(test_module.LedgerConfigError):
                conductor.handle_not_returned(conductor.root_profile, message)

            mock_dispatch_run.assert_called_once()
            mock_notify.assert_called_once()

    async def test_queue_outbound_ledger_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings_admin)
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            test_module, "ConnectionManager", autospec=True
        ) as conn_mgr, async_mock.patch.object(
            conductor.dispatcher, "run_task", async_mock.MagicMock()
        ) as mock_dispatch_run, async_mock.patch.object(
            conductor.admin_server, "notify_fatal_error", async_mock.MagicMock()
        ) as mock_notify:
            conn_mgr.return_value.get_connection_targets = async_mock.CoroutineMock()
            mock_dispatch_run.side_effect = test_module.LedgerConfigError(
                "No such ledger"
            )

            payload = "{}"
            message = OutboundMessage(
                payload=payload,
                connection_id="dummy-conn-id",
                reply_to_verkey=TestDIDs.test_verkey,
            )

            with self.assertRaises(test_module.LedgerConfigError):
                await conductor.queue_outbound(conductor.root_profile, message)

            mock_dispatch_run.assert_called_once()
            mock_notify.assert_called_once()

    async def test_admin(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"admin.enabled": "1"})
        conductor = test_module.Conductor(builder)

        await conductor.setup()
        admin = conductor.context.inject(BaseAdminServer)
        assert admin is conductor.admin_server

        session = await conductor.root_profile.session()
        wallet = session.inject(BaseWallet)
        await wallet.create_public_did()

        with async_mock.patch.object(
            admin, "start", autospec=True
        ) as admin_start, async_mock.patch.object(
            admin, "stop", autospec=True
        ) as admin_stop:
            await conductor.start()
            admin_start.assert_awaited_once_with()

            await conductor.stop()
            admin_stop.assert_awaited_once_with()

    async def test_admin_startx(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings(
            {
                "admin.enabled": "1",
                "debug.print_invitation": True,
                "debug.print_connections_invitation": True,
            }
        )
        conductor = test_module.Conductor(builder)

        await conductor.setup()
        admin = conductor.context.inject(BaseAdminServer)
        assert admin is conductor.admin_server

        session = await conductor.root_profile.session()
        wallet = session.inject(BaseWallet)
        await wallet.create_public_did()

        with async_mock.patch.object(
            admin, "start", autospec=True
        ) as admin_start, async_mock.patch.object(
            admin, "stop", autospec=True
        ) as admin_stop, async_mock.patch.object(
            test_module, "OutOfBandManager"
        ) as oob_mgr, async_mock.patch.object(
            test_module, "ConnectionManager"
        ) as conn_mgr:
            admin_start.side_effect = KeyError("trouble")
            oob_mgr.return_value.create_invitation = async_mock.CoroutineMock(
                side_effect=KeyError("double trouble")
            )
            conn_mgr.return_value.create_invitation = async_mock.CoroutineMock(
                side_effect=KeyError("triple trouble")
            )
            await conductor.start()
            admin_start.assert_awaited_once_with()

            await conductor.stop()
            admin_stop.assert_awaited_once_with()

    async def test_setup_collector(self):
        builder: ContextBuilder = StubCollectorContextBuilder(self.test_settings)
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "InboundTransportManager", autospec=True
        ) as mock_inbound_mgr, async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr, async_mock.patch.object(
            test_module, "LoggingConfigurator", autospec=True
        ) as mock_logger:

            await conductor.setup()

    async def test_start_static(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"debug.test_suite_endpoint": True})
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(test_module, "ConnectionManager") as mock_mgr:
            await conductor.setup()

            session = await conductor.root_profile.session()
            wallet = session.inject(BaseWallet)
            await wallet.create_public_did()

            mock_mgr.return_value.create_static_connection = async_mock.CoroutineMock()
            await conductor.start()
            mock_mgr.return_value.create_static_connection.assert_awaited_once()

    async def test_start_x_in(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"debug.test_suite_endpoint": True})
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "ConnectionManager"
        ) as mock_mgr, async_mock.patch.object(
            test_module, "InboundTransportManager"
        ) as mock_intx_mgr:
            mock_intx_mgr.return_value = async_mock.MagicMock(
                setup=async_mock.CoroutineMock(),
                start=async_mock.CoroutineMock(side_effect=KeyError("trouble")),
            )
            await conductor.setup()
            mock_mgr.return_value.create_static_connection = async_mock.CoroutineMock()
            with self.assertRaises(KeyError):
                await conductor.start()

    async def test_start_x_out(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"debug.test_suite_endpoint": True})
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "ConnectionManager"
        ) as mock_mgr, async_mock.patch.object(
            test_module, "OutboundTransportManager"
        ) as mock_outx_mgr:
            mock_outx_mgr.return_value = async_mock.MagicMock(
                setup=async_mock.CoroutineMock(),
                start=async_mock.CoroutineMock(side_effect=KeyError("trouble")),
            )
            await conductor.setup()
            mock_mgr.return_value.create_static_connection = async_mock.CoroutineMock()
            with self.assertRaises(KeyError):
                await conductor.start()

    async def test_dispatch_complete_non_fatal_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings_admin)
        conductor = test_module.Conductor(builder)

        message_body = "{}"
        receipt = MessageReceipt(direct_response_mode="snail mail")
        message = InboundMessage(message_body, receipt)
        mock_task = async_mock.MagicMock(
            exc_info=(KeyError, KeyError("sample exception"), "..."),
            ident="abc",
            timing={
                "queued": 1234567890,
                "unqueued": 1234567899,
                "started": 1234567901,
                "ended": 1234567999,
            },
        )

        await conductor.setup()

        with async_mock.patch.object(
            conductor.admin_server, "notify_fatal_error", async_mock.MagicMock()
        ) as mock_notify:
            conductor.dispatch_complete(message, mock_task)
            mock_notify.assert_not_called()

    async def test_dispatch_complete_fatal_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings_admin)
        conductor = test_module.Conductor(builder)

        message_body = "{}"
        receipt = MessageReceipt(direct_response_mode="snail mail")
        message = InboundMessage(message_body, receipt)
        mock_task = async_mock.MagicMock(
            exc_info=(
                test_module.LedgerTransactionError,
                test_module.LedgerTransactionError("Ledger is wobbly"),
                "...",
            ),
            ident="abc",
            timing={
                "queued": 1234567890,
                "unqueued": 1234567899,
                "started": 1234567901,
                "ended": 1234567999,
            },
        )

        await conductor.setup()

        with async_mock.patch.object(
            conductor.admin_server, "notify_fatal_error", async_mock.MagicMock()
        ) as mock_notify:
            conductor.dispatch_complete(message, mock_task)
            mock_notify.assert_called_once_with()

    async def test_print_invite_connection(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings(
            {
                "debug.print_invitation": True,
                "debug.print_connections_invitation": True,
                "invite_base_url": "http://localhost",
            }
        )
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch("sys.stdout", new=StringIO()) as captured:
            await conductor.setup()

            session = await conductor.root_profile.session()
            wallet = session.inject(BaseWallet)
            await wallet.create_public_did()

            await conductor.start()
            await conductor.stop()
            value = captured.getvalue()
            assert "http://localhost?oob=" in value
            assert "http://localhost?c_i=" in value

    async def test_mediator_invitation(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"mediation.invite": "test-invite"})
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        mock_conn_record = async_mock.MagicMock()

        with async_mock.patch.object(
            test_module.ConnectionInvitation, "from_url"
        ) as mock_from_url, async_mock.patch.object(
            test_module,
            "ConnectionManager",
            async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    receive_invitation=async_mock.CoroutineMock(
                        return_value=mock_conn_record
                    )
                )
            ),
        ) as mock_mgr, async_mock.patch.object(
            mock_conn_record, "metadata_set", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            test_module,
            "LOGGER",
            async_mock.MagicMock(
                exception=async_mock.MagicMock(
                    side_effect=Exception("This method should not have been called")
                )
            ),
        ):
            await conductor.start()
            await conductor.stop()
            mock_from_url.assert_called_once_with("test-invite")
            mock_mgr.return_value.receive_invitation.assert_called_once()

    async def test_mediator_invitation_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"mediation.invite": "test-invite"})
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            test_module.ConnectionInvitation,
            "from_url",
            async_mock.MagicMock(side_effect=Exception()),
        ) as mock_from_url, async_mock.patch.object(
            test_module, "LOGGER"
        ) as mock_logger:
            await conductor.start()
            await conductor.stop()
            mock_from_url.assert_called_once_with("test-invite")
            mock_logger.exception.assert_called_once()

    async def test_clear_default_mediator(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"mediation.clear": True})
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            test_module,
            "MediationManager",
            return_value=async_mock.MagicMock(
                clear_default_mediator=async_mock.CoroutineMock()
            ),
        ) as mock_mgr:
            await conductor.start()
            await conductor.stop()
            mock_mgr.return_value.clear_default_mediator.assert_called_once()

    async def test_set_default_mediator(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"mediation.default_id": "test-id"})
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            test_module,
            "MediationManager",
            return_value=async_mock.MagicMock(
                set_default_mediator=async_mock.CoroutineMock()
            ),
        ) as mock_mgr, async_mock.patch.object(
            test_module.MediationRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ), async_mock.patch.object(
            test_module,
            "LOGGER",
            async_mock.MagicMock(
                exception=async_mock.MagicMock(
                    side_effect=Exception("This method should not have been called")
                )
            ),
        ):
            await conductor.start()
            await conductor.stop()
            mock_mgr.return_value.set_default_mediator.assert_called_once()

    async def test_set_default_mediator_x(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings({"mediation.default_id": "test-id"})
        conductor = test_module.Conductor(builder)

        await conductor.setup()

        with async_mock.patch.object(
            test_module.MediationRecord,
            "retrieve_by_id",
            async_mock.CoroutineMock(side_effect=Exception()),
        ), async_mock.patch.object(test_module, "LOGGER") as mock_logger:
            await conductor.start()
            await conductor.stop()
            mock_logger.exception.assert_called_once()

    async def test_webhook_router(self):
        builder: ContextBuilder = StubContextBuilder(self.test_settings)
        builder.update_settings(
            {"debug.print_invitation": True, "invite_base_url": "http://localhost"}
        )
        conductor = test_module.Conductor(builder)

        test_topic = "test-topic"
        test_payload = {"test": "payload"}
        test_endpoint = "http://example"
        test_attempts = 2

        await conductor.setup()
        with async_mock.patch.object(
            conductor.outbound_transport_manager, "enqueue_webhook"
        ) as mock_enqueue:
            conductor.webhook_router(
                test_topic, test_payload, test_endpoint, test_attempts
            )
            mock_enqueue.assert_called_once_with(
                test_topic, test_payload, test_endpoint, test_attempts, None
            )

        # swallow error
        with async_mock.patch.object(
            conductor.outbound_transport_manager,
            "enqueue_webhook",
            side_effect=OutboundDeliveryError,
        ) as mock_enqueue:
            conductor.webhook_router(
                test_topic, test_payload, test_endpoint, test_attempts
            )
            mock_enqueue.assert_called_once_with(
                test_topic, test_payload, test_endpoint, test_attempts, None
            )

    async def test_shutdown_multitenant_profiles(self):
        builder: ContextBuilder = StubContextBuilder(
            {**self.test_settings, "multitenant.enabled": True}
        )
        conductor = test_module.Conductor(builder)

        with async_mock.patch.object(
            test_module, "InboundTransportManager", autospec=True
        ) as mock_inbound_mgr, async_mock.patch.object(
            test_module, "OutboundTransportManager", autospec=True
        ) as mock_outbound_mgr, async_mock.patch.object(
            test_module, "LoggingConfigurator", autospec=True
        ) as mock_logger:

            await conductor.setup()

            multitenant_mgr = conductor.context.inject(MultitenantManager)

            await multitenant_mgr._profiles.put(
                "test1", async_mock.MagicMock(close=async_mock.CoroutineMock())
            )
            await multitenant_mgr._profiles.put(
                "test2", async_mock.MagicMock(close=async_mock.CoroutineMock())
            )

            await conductor.stop()

            multitenant_mgr._profiles.get("test1").close.assert_called_once_with()
            multitenant_mgr._profiles.get("test2").close.assert_called_once_with()
