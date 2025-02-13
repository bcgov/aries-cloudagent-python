from unittest import IsolatedAsyncioTestCase

from aries_askar import AskarError

from acapy_agent.askar.profile import AskarProfileSession
from acapy_agent.did.indy.indy_manager import DidIndyManager
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import KeyTypes


class TestIndyManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(
            DIDMethods, mock.MagicMock(DIDMethods, auto_spec=True)
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())

    def test_init(self):
        assert DidIndyManager(self.profile)

    @mock.patch.object(AskarProfileSession, "handle")
    async def test_register(self, mock_handle):
        mock_handle.insert_key = mock.CoroutineMock()
        mock_handle.insert = mock.CoroutineMock()
        manager = DidIndyManager(self.profile)
        result = await manager.register({})
        assert result.get("did")
        assert result.get("verkey")
        mock_handle.insert_key.assert_called_once()
        mock_handle.insert.assert_called_once()

        # error saving key
        mock_handle.insert_key.side_effect = AskarError(
            code=1, message="Error saving key"
        )
        with self.assertRaises(WalletError):
            await manager.register({})

    @mock.patch.object(AskarProfileSession, "handle")
    async def test_register_with_seed_with_key_type(self, mock_handle):
        mock_handle.insert_key = mock.CoroutineMock()
        mock_handle.insert = mock.CoroutineMock()
        manager = DidIndyManager(self.profile)

        result = await manager.register({"key_type": "ed25519"})
        assert result.get("did")
        assert result.get("verkey")

    @mock.patch.object(AskarProfileSession, "handle")
    async def test_register_with_seed_with_defined_did(self, mock_handle):
        mock_handle.insert_key = mock.CoroutineMock()
        mock_handle.insert = mock.CoroutineMock()
        manager = DidIndyManager(self.profile)

        result = await manager.register({"did": "did:indy:WRfXPg8dantKVubE3HX8pw"})
        assert result.get("did") == "did:indy:WRfXPg8dantKVubE3HX8pw"
        assert result.get("verkey")

    @mock.patch.object(AskarProfileSession, "handle")
    async def test_register_with_seed_with_all_options(self, mock_handle):
        self.profile.settings.set_value("wallet.allow_insecure_seed", True)
        mock_handle.insert_key = mock.CoroutineMock()
        mock_handle.insert = mock.CoroutineMock()
        manager = DidIndyManager(self.profile)

        result = await manager.register(
            {
                "did": "did:indy:WRfXPg8dantKVubE3HX8pw",
                "key_type": "ed25519",
                "seed": "000000000000000000000000Trustee1",
            }
        )
        assert result.get("did") == "did:indy:WRfXPg8dantKVubE3HX8pw"
        assert result.get("verkey")
