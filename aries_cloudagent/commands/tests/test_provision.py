import pytest

from asynctest import mock as async_mock, TestCase as AsyncTestCase

from ...config.base import ConfigError
from ...config.error import ArgsParseError
from ...core.profile import Profile
from .. import provision as test_module


class TestProvision(AsyncTestCase):
    def test_bad_calls(self):
        with self.assertRaises(SystemExit):
            test_module.execute([])

        with self.assertRaises(SystemExit):
            test_module.execute(["bad"])

    @pytest.mark.indy
    def test_provision_wallet(self):
        test_seed = "testseed000000000000000000000001"
        test_module.execute(
            [
                "--wallet-type",
                "indy",
                "--wallet-name",
                "test_wallet",
                "--wallet-key",
                "key",
                "--seed",
                test_seed,
                "--no-ledger",
                "--endpoint",
                "test_endpoint",
                "--recreate-wallet",
            ]
        )

    async def test_provision_ledger_configured(self):
        profile = async_mock.MagicMock(close=async_mock.CoroutineMock())
        with async_mock.patch.object(
            test_module,
            "wallet_config",
            async_mock.CoroutineMock(
                return_value=(
                    profile,
                    async_mock.CoroutineMock(did="public DID", verkey="verkey"),
                )
            ),
        ) as mock_wallet_config, async_mock.patch.object(
            test_module, "ledger_config", async_mock.CoroutineMock(return_value=True)
        ) as mock_ledger_config:
            await test_module.provision({})

    async def test_provision_config_x(self):
        with async_mock.patch.object(
            test_module, "wallet_config", async_mock.CoroutineMock()
        ) as mock_wallet_config:
            mock_wallet_config.side_effect = ConfigError("oops")
            with self.assertRaises(test_module.ProvisionError):
                await test_module.provision({})

    def test_main(self):
        with async_mock.patch.object(
            test_module, "__name__", "__main__"
        ) as mock_name, async_mock.patch.object(
            test_module, "execute", async_mock.MagicMock()
        ) as mock_execute:
            test_module.main()
            mock_execute.assert_called_once
