from unittest import IsolatedAsyncioTestCase

from .....admin.request_context import AdminRequestContext
from .....tests import mock
from .....utils.testing import create_test_profile
from .. import routes as test_module
from .....wallet.did_method import (
    DIDMethods,
)

# from didcomm_messaging import DIDCommMessaging, RoutingService
from didcomm_messaging.resolver import DIDResolver as DMPResolver
from didcomm_messaging import (
    CryptoService,
    DIDCommMessaging,
    PackagingService,
    RoutingService,
    SecretsManager,
)
from didcomm_messaging.crypto.backend.askar import AskarCryptoService


class TestTrustpingRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.session_inject = {}
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "secret-key",
            }
        )
        self.context = AdminRequestContext.test_context(self.session_inject, self.profile)
        self.context.injector.bind_instance(DIDMethods, DIDMethods())
        from .....didcomm_v2.adapters import ResolverAdapter, SecretsAdapter
        from .....resolver.did_resolver import DIDResolver
        from .....resolver.default.peer4 import PeerDID4Resolver

        self.context.injector.bind_instance(DIDResolver, DIDResolver())
        didResolver = self.context.inject_or(DIDResolver)
        self.context.injector.bind_instance(
            DMPResolver, ResolverAdapter(self.profile, didResolver)
        )
        self.context.injector.bind_instance(SecretsManager, SecretsAdapter(self.profile))
        self.context.injector.bind_instance(RoutingService, RoutingService())
        self.context.injector.bind_instance(CryptoService, AskarCryptoService())
        self.context.injector.bind_instance(PackagingService, PackagingService())
        peer_did_4_resolver = PeerDID4Resolver()
        await peer_did_4_resolver.setup(self.context)
        didResolver.register_resolver(peer_did_4_resolver)

        self.context.injector.bind_instance(
            DIDCommMessaging,
            DIDCommMessaging(
                self.context.inject_or(CryptoService),
                self.context.inject_or(SecretsManager),
                self.context.inject_or(DMPResolver),
                self.context.inject_or(PackagingService),
                self.context.inject_or(RoutingService),
            ),
        )

        self.request_dict = {
            "context": self.context,
            "outbound_message_router": mock.CoroutineMock(),
        }
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

    async def test_connections_send_ping(self):
        DID = "did:peer:4zQmXrH3ADfT6LtLQgrVkQtitAnYtQaEaaonP8yehJv79DAD:z6uysxxSHsMeCGVLxaA5yaTNMqkacZmod7a5nG9Seq8SNjt8NqK7oXreduL22hybjVvWgUA6TVq9enGQC3PP3RU3tKvxfnPhvYDrs3CoYx8VsdFvbuUVYGhsxPVgg8yByGgV6kmteqdACzThtpVLCXcLcxuxJj4i6v3W2AMyUTKy18aPbupzMMBLbdxsuVT1ePydY4AuB2VpVPz1XRxBJZjzQd1Va6BnzCPS9y87XpZwS8hc5GQcqss7XG1Pmmq3xCbiKzSBfx3NL6sxgWY1Vuc3aYaPXkXEtAvMbUnbyGx9UDY6rozLdv2WnyHP6B9krNz4TgfoTFSz9exNctKt7BTNuPi5cgEhAEKs81sqAKSQbuN514mrsAU3QEyEGFH46Wnfm1PxDwwhg4E6oqxKTxykvz698MuZijAr8nD6fV9gMLoF2FHSyqn21CQZXsWC5ZTo534HbjVNEifEkev493JdZQTLmTkA8rdEnnCBwSgXaHMtPmYbd6XzSj4PVKa31K14Q2ktrxkic7kTVSf5Dv9mzvUgD4iUSmtsxj2VrBNaZHFbWYD8QANJY6H6NRt9WjwZDypLdPDmUZDzNLmqxSxdxT5DYxboVPtuh9dWtT7tpeDuzD6XBs9jjw5cSZ7DWWRSvTWuovm9sSuSC8zdCuzRrHFu6JaYDVHujyUvNyQ3cJ4EJxvb4LjmaCfZiuY6VvtGSkdyxoe22PyH3eBVzgwxYN7XPDCc7ewE8uS76x7PC2qWnFzrXCHaP51jg3cZtXoysktXGsvZ8B1XnZJYTteS5GJmaUgZYD9QsKSyq3GEiygzBN1StPSopBzpAscdfH4VtGNbrBYNCVBaGQetJfm9FV9HRyk1XJHTGe5JTBb2862dGHY7zmpinwM4XriPRizGPkEVE3FJddFUrmMz6iRMpDp7ZyxeYUrnGN94vW8nuPa77CkyPu82LkdJgrFfAwGyB6B26Br3YmBPBH8af1uKSfufgyZr4KqFL3NFDp8DPPvMSgJaxVnHdjYnCWYDJWaoFR3LKMdBiH1Z894akrb4DEGNVV7YSZoWLEAtRiDP87526z9pv85QiZyau6St4L2bMfEnYcR5TDQtj4oWGbZtfxTbURWZr2RoCdo9vQSa1YFjrN8rX3ob8CCeexRb38eJj9o5gRaVdij3JZyxPDuHDQHBUeAU75RueK2QCHTCBAkhp1JrFLGiHuTrfX6Q1HmpE2YVyoabybCHuu7joMZrVmCkmbYUhPXmFXd2mX3drBApVdxvrbS4VJZxzVETTnDnXxSeVffubam4cWZGaHHzjUUJ593wkWwbnafjUxoQHeH5gRE9fo7stAWCNn4hYRFdTVKRe4zC7pkLXcTThRvZDHwhixPaxKYFXAd5Vhkixo5DLjvt8t4kBZEDfBmNxef1Bkf3TUXAW7bh21SMjSwzekQuVezZwYjiTMPCPMXPv7BvRQfT3NqftD45B3TkAbYXRCo5t18fJt6eKfEvQYyJQbJbgJHvvJyPM54t9z4y9qQtJEPGNNAhbwmttoshCznEkYEpLBUXiffXyS6LDjSURntutCL2GQp8YBMup9xEm32o44NupwND56a78dxdoF9XDxwp8vvY89rTsPGX2bRMyFW8uyXyyrwpnqQMoykidWrBexjTYc4oZpRzHznaVXnLxsWZRqKCdthw2jmTyxDoJncWvnpLHRWNwW44oP1pzCHMf9nwunySm6dp79wMKo5tmfanFud596J237C8MhZc4sFcknPC2BkeBqu4E5WryhA2ZCAmiNqKg6EjPbhEAG45yT1gw9fTtA3ydqwvarsUyXT7DKPjwasSAY6VD5iyzKpC1obEoXTzCb5sVmtUDFywArUGChPed8uVzaWyN73vJqo6SG"
        self.request.json = mock.CoroutineMock(return_value={"to_did": DID})
        self.request.match_info = {"to_did": DID}

        with (
            mock.patch.object(
                test_module, "V2AgentMessage", mock.MagicMock()
            ) as mock_ping,
            mock.patch.object(test_module, "get_mydid", mock.CoroutineMock()) as mock_did,
            mock.patch.object(
                test_module.web, "json_response", mock.MagicMock()
            ) as json_response,
        ):
            mock_ping.return_value = mock.MagicMock(_thread_id="dummy")
            mock_did.return_value = mock.CoroutineMock(return_value=DID)
            # mock_retrieve.return_value = mock.MagicMock(is_ready=True)
            result = await test_module.connections_send_ping(self.request)
            expected = mock_ping(
                message={
                    "type": "https://didcomm.org/trust-ping/2.0/ping",
                    "body": {},
                    "to": [DID],
                    "from": DID,
                }
            )
            json_response.assert_called_once_with(expected.message)
            assert result is json_response.return_value

    # async def test_connections_send_ping_no_conn(self):
    #     self.request.json = mock.CoroutineMock(return_value={"comment": "some comment"})
    #     self.request.match_info = {"conn_id": "dummy"}

    #     with (
    #         mock.patch.object(test_module.web, "json_response", mock.MagicMock()),
    #     ):
    #         # mock_retrieve.side_effect = test_module.StorageNotFoundError()
    #         with self.assertRaises(test_module.web.HTTPNotFound):
    #             await test_module.connections_send_ping(self.request)

    # async def test_connections_send_ping_not_ready(self):
    #     self.request.json = mock.CoroutineMock(return_value={"comment": "some comment"})
    #     self.request.match_info = {"conn_id": "dummy"}

    #     with (
    #         mock.patch.object(test_module.web, "json_response", mock.MagicMock()),
    #     ):
    #         # mock_retrieve.return_value = mock.MagicMock(is_ready=False)
    #         with self.assertRaises(test_module.web.HTTPBadRequest):
    #             await test_module.connections_send_ping(self.request)

    async def test_register(self):
        mock_app = mock.MagicMock()
        mock_app.add_routes = mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called_once()

    async def test_post_process_routes(self):
        mock_app = mock.MagicMock(_state={"swagger_dict": {}})
        test_module.post_process_routes(mock_app)
        assert "tags" in mock_app._state["swagger_dict"]
