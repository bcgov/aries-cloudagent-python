import asyncio
from unittest import IsolatedAsyncioTestCase
from uuid import uuid4

from ...askar.profile import AskarProfile
from ...config.injection_context import InjectionContext
from ...messaging.responder import BaseResponder
from ...tests import mock
from ...utils.testing import create_test_profile
from ...wallet.models.wallet_record import WalletRecord
from ..single_wallet_askar_manager import SingleWalletAskarMultitenantManager


class TestSingleWalletAskarMultitenantManager(IsolatedAsyncioTestCase):
    DEFAULT_MULTIENANT_WALLET_NAME = "multitenant_sub_wallet"

    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.context = self.profile.context

        self.responder = mock.CoroutineMock(send=mock.CoroutineMock())
        self.context.injector.bind_instance(BaseResponder, self.responder)

        self.manager = SingleWalletAskarMultitenantManager(self.profile)

    async def test_get_wallet_profile_should_open_store_and_return_profile_with_wallet_context(
        self,
    ):
        askar_profile_mock_name = "AskarProfile"
        wallet_name = "unit_testing/" + str(uuid4())
        wallet_record = WalletRecord(
            wallet_id="test",
            settings={
                "wallet.recreate": True,
                "wallet.seed": "test_seed",
                "wallet.name": wallet_name,
                "wallet.type": "test_type",
                "wallet.rekey": "test_rekey",
                "mediation.open": True,
                "mediation.invite": "http://invite.com",
                "mediation.default_id": "24a96ef5",
                "mediation.clear": True,
            },
        )

        with (
            mock.patch(
                "acapy_agent.multitenant.single_wallet_askar_manager.wallet_config"
            ) as wallet_config,
            mock.patch(
                "acapy_agent.multitenant.single_wallet_askar_manager.AskarProfile",
            ) as AskarProfile,
        ):
            sub_wallet_profile_context = InjectionContext()
            sub_wallet_profile = await AskarProfile.create(None, None)
            sub_wallet_profile.context.copy.return_value = sub_wallet_profile_context

            def side_effect(context, provision):
                sub_wallet_profile.name = askar_profile_mock_name
                return sub_wallet_profile, None

            wallet_config.side_effect = side_effect

            profile = await self.manager.get_wallet_profile(
                self.profile.context, wallet_record
            )

            assert profile.name == askar_profile_mock_name
            wallet_config.assert_called_once()
            wallet_config_settings_argument = wallet_config.call_args[0][0].settings
            assert (
                wallet_config_settings_argument.get("wallet.name")
                == self.DEFAULT_MULTIENANT_WALLET_NAME
            )
            assert wallet_config_settings_argument.get("wallet.id") is None
            assert wallet_config_settings_argument.get("auto_provision") is True
            assert wallet_config_settings_argument.get("wallet.type") == "askar"
            AskarProfile.assert_called_with(
                sub_wallet_profile.opened, sub_wallet_profile_context, profile_id="test"
            )
            assert sub_wallet_profile_context.settings.get("wallet.seed") == "test_seed"
            assert sub_wallet_profile_context.settings.get("wallet.rekey") == "test_rekey"
            assert sub_wallet_profile_context.settings.get("wallet.name") == wallet_name
            assert sub_wallet_profile_context.settings.get("wallet.type") == "test_type"
            assert sub_wallet_profile_context.settings.get("mediation.open") is True
            assert (
                sub_wallet_profile_context.settings.get("mediation.invite")
                == "http://invite.com"
            )
            assert (
                sub_wallet_profile_context.settings.get("mediation.default_id")
                == "24a96ef5"
            )
            assert sub_wallet_profile_context.settings.get("mediation.clear") is True
            assert (
                sub_wallet_profile_context.settings.get("wallet.id")
                == wallet_record.wallet_id
            )
            assert sub_wallet_profile_context.settings.get("wallet.name") == wallet_name
            assert (
                sub_wallet_profile_context.settings.get("wallet.askar_profile")
                == wallet_record.wallet_id
            )

    async def test_get_anoncreds_wallet_profile_should_open_store_and_return_anoncreds_profile(
        self,
    ):
        askar_profile_mock_name = "AskarProfile"
        wallet_name = "unit_testing/" + str(uuid4())
        wallet_record = WalletRecord(
            wallet_id="test",
            settings={
                "wallet.recreate": True,
                "wallet.seed": "test_seed",
                "wallet.name": wallet_name,
                "wallet.type": "askar-anoncreds",
                "wallet.rekey": "test_rekey",
            },
        )

        with (
            mock.patch(
                "acapy_agent.multitenant.single_wallet_askar_manager.wallet_config"
            ) as wallet_config,
            mock.patch(
                "acapy_agent.multitenant.single_wallet_askar_manager.AskarAnoncredsProfile",
            ) as AskarAnoncredsProfile,
        ):
            sub_wallet_profile_context = InjectionContext()
            sub_wallet_profile = await AskarAnoncredsProfile.create(None, None)
            sub_wallet_profile.context.copy.return_value = sub_wallet_profile_context

            def side_effect(context, provision):
                sub_wallet_profile.name = askar_profile_mock_name
                return sub_wallet_profile, None

            wallet_config.side_effect = side_effect

            await self.manager.get_wallet_profile(self.profile.context, wallet_record)

            AskarAnoncredsProfile.assert_called_with(
                sub_wallet_profile.opened, sub_wallet_profile_context, profile_id="test"
            )

    async def test_get_wallet_profile_should_create_profile(self):
        wallet_record = WalletRecord(wallet_id="test", settings={})
        create_profile_stub = asyncio.Future()
        create_profile_stub.set_result("")

        with mock.patch(
            "acapy_agent.multitenant.single_wallet_askar_manager.AskarProfile"
        ) as AskarProfile:
            sub_wallet_profile = await AskarProfile.create(None, None)
            sub_wallet_profile.context.copy.return_value = InjectionContext()
            sub_wallet_profile.store.create_profile.return_value = create_profile_stub
            self.manager._multitenant_profile = sub_wallet_profile

            await self.manager.get_wallet_profile(
                self.profile.context, wallet_record, provision=True
            )

            sub_wallet_profile.store.create_profile.assert_called_once_with(
                wallet_record.wallet_id
            )

    async def test_get_wallet_profile_should_use_custom_subwallet_name(self):
        wallet_record = WalletRecord(wallet_id="test", settings={})
        multitenant_sub_wallet_name = "custom_wallet_name"
        self.profile.context.settings = self.profile.settings.extend(
            {"multitenant.wallet_name": multitenant_sub_wallet_name}
        )

        with mock.patch(
            "acapy_agent.multitenant.single_wallet_askar_manager.wallet_config"
        ) as wallet_config:
            with mock.patch(
                "acapy_agent.multitenant.single_wallet_askar_manager.AskarProfile"
            ) as AskarProfile:
                sub_wallet_profile = await AskarProfile.create(None, None)
                sub_wallet_profile.context.copy.return_value = InjectionContext()

                def side_effect(context, provision):
                    return sub_wallet_profile, None

                wallet_config.side_effect = side_effect

                await self.manager.get_wallet_profile(self.profile.context, wallet_record)

                wallet_config.assert_called_once()
                assert (
                    wallet_config.call_args[0][0].settings.get("wallet.name")
                    == multitenant_sub_wallet_name
                )

    async def test_remove_wallet_profile(self):
        test_profile = await create_test_profile({"wallet.id": "test"})

        with mock.patch.object(AskarProfile, "remove") as profile_remove:
            await self.manager.remove_wallet_profile(test_profile)
            profile_remove.assert_called_once_with()

    async def test_open_profiles(self):
        assert len(list(self.manager.open_profiles)) == 0

        create_profile_stub = asyncio.Future()
        create_profile_stub.set_result("")
        with mock.patch(
            "acapy_agent.multitenant.single_wallet_askar_manager.AskarProfile"
        ) as AskarProfile:
            sub_wallet_profile = await AskarProfile.create(None, None)
            sub_wallet_profile.context.copy.return_value = InjectionContext()
            sub_wallet_profile.store.create_profile.return_value = create_profile_stub
            self.manager._multitenant_profile = sub_wallet_profile

        assert len(list(self.manager.open_profiles)) == 1
