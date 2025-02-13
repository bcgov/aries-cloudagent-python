from unittest import IsolatedAsyncioTestCase

from aiohttp import web

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.did.indy.indy_manager import DidIndyManager
from acapy_agent.did.indy.routes import create_indy_did
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.error import WalletError


class TestDidIndyRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.session_inject = {}
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "secret-key",
            },
        )
        self.context = AdminRequestContext.test_context(self.session_inject, self.profile)
        self.request_dict = {
            "context": self.context,
        }
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            context=self.context,
            headers={"x-api-key": "secret-key"},
        )

    @mock.patch.object(
        DidIndyManager,
        "register",
        return_value={"did": "did:indy:DFZgMggBEXcZFVQ2ZBTwdr", "verkey": "BnSWTUQmdYC"},
    )
    async def test_create_indy_did(self, mock_register):
        self.profile.context.injector.bind_instance(
            DIDMethods, mock.MagicMock(DIDMethods, auto_spec=True)
        )
        self.request.json = mock.CoroutineMock(return_value={})
        response = await create_indy_did(self.request)
        assert response.status == 200
        assert mock_register.called

        self.request.json = mock.CoroutineMock(
            return_value={
                "features": {},
                "options": {
                    "did": "did:indy:WRfXPg8dantKVubE3HX8pw",
                    "key_type": "ed25519",
                },
            }
        )
        response = await create_indy_did(self.request)
        assert response.status == 200
        assert mock_register.called

    @mock.patch.object(
        DidIndyManager,
        "register",
        side_effect=[WalletError("Error creating DID")],
    )
    async def test_create_indy_did_wallet_error(self, _):
        self.profile.context.injector.bind_instance(
            DIDMethods, mock.MagicMock(DIDMethods, auto_spec=True)
        )
        self.request.json = mock.CoroutineMock(return_value={})
        with self.assertRaises(web.HTTPBadRequest):
            await create_indy_did(self.request)
