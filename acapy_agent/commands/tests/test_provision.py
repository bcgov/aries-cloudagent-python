from unittest import IsolatedAsyncioTestCase

from acapy_agent.tests import mock

from ...config.base import ConfigError
from ...config.error import ArgsParseError
from ...protocols.coordinate_mediation.mediation_invite_store import (
    MediationInviteRecord,
)
from ...utils.testing import create_test_profile
from .. import provision as test_module


class TestProvision(IsolatedAsyncioTestCase):
    def test_bad_calls(self):
        with self.assertRaises(ArgsParseError):
            test_module.execute([])

        with self.assertRaises(SystemExit):
            test_module.execute(["bad"])

    async def test_provision_ledger_configured(self):
        profile = mock.MagicMock(close=mock.CoroutineMock())
        with (
            mock.patch.object(
                test_module,
                "wallet_config",
                mock.CoroutineMock(
                    return_value=(
                        profile,
                        mock.CoroutineMock(did="public DID", verkey="verkey"),
                    )
                ),
            ),
            mock.patch.object(
                test_module, "ledger_config", mock.CoroutineMock(return_value=True)
            ),
        ):
            await test_module.provision({})

    async def test_provision_config_x(self):
        with mock.patch.object(
            test_module, "wallet_config", mock.CoroutineMock()
        ) as mock_wallet_config:
            mock_wallet_config.side_effect = ConfigError("oops")
            with self.assertRaises(test_module.ProvisionError):
                await test_module.provision({})

    def test_main(self):
        with (
            mock.patch.object(test_module, "__name__", "__main__"),
            mock.patch.object(test_module, "execute", mock.MagicMock()) as mock_execute,
        ):
            test_module.main()
            mock_execute.assert_called_once

    async def test_provision_should_store_provided_mediation_invite(self):
        # given
        mediation_invite = "test-invite"
        test_profile = await create_test_profile()

        with (
            mock.patch.object(test_module.MediationInviteStore, "store") as invite_store,
            mock.patch.object(
                test_module,
                "wallet_config",
                mock.CoroutineMock(return_value=(test_profile, mock.MagicMock())),
            ),
        ):
            # when
            await test_module.provision({"mediation.invite": mediation_invite})

            # then
            invite_store.assert_called_with(
                MediationInviteRecord(mediation_invite, False)
            )
