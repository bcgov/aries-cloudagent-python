import asyncio
from unittest import mock

import pytest

from ...askar.profile import AskarProfile, AskarProfileManager
from ...config.injection_context import InjectionContext
from ...ledger.base import BaseLedger
from .. import profile as test_module
from ..profile_anon import AskarAnonProfileManager


@pytest.fixture
def open_store():
    yield mock.MagicMock()


@pytest.mark.asyncio
async def test_init_success(open_store):
    askar_profile = await AskarProfile.create(
        open_store,
    )

    assert askar_profile.opened == open_store


@pytest.mark.asyncio
async def test_init_multi_ledger(open_store):
    context = InjectionContext(
        settings={
            "ledger.ledger_config_list": [
                {
                    "id": "BCovrinDev",
                    "is_production": True,
                    "is_write": True,
                    "endorser_did": "9QPa6tHvBHttLg6U4xvviv",
                    "endorser_alias": "endorser_dev",
                    "genesis_transactions": mock.MagicMock(),
                },
                {
                    "id": "SovrinStagingNet",
                    "is_production": False,
                    "genesis_transactions": mock.MagicMock(),
                },
            ]
        }
    )
    askar_profile = await AskarProfile.create(
        open_store,
        context=context,
    )

    assert askar_profile.opened == open_store
    assert askar_profile.settings["endorser.endorser_alias"] == "endorser_dev"
    assert (
        askar_profile.settings["endorser.endorser_public_did"] == "9QPa6tHvBHttLg6U4xvviv"
    )
    assert (askar_profile.inject_or(BaseLedger)).pool_name == "BCovrinDev"


@pytest.mark.asyncio
async def test_remove_success(open_store):
    openStore = open_store
    context = InjectionContext()
    profile_id = "profile_id"
    context.settings = {
        "multitenant.wallet_type": "single-wallet-askar",
        "wallet.askar_profile": profile_id,
        "ledger.genesis_transactions": mock.MagicMock(),
    }
    askar_profile = await AskarProfile.create(openStore, context, profile_id=profile_id)
    remove_profile_stub = asyncio.Future()
    remove_profile_stub.set_result(True)
    openStore.store.remove_profile.return_value = remove_profile_stub

    await askar_profile.remove()

    openStore.store.remove_profile.assert_called_once_with(profile_id)


@pytest.mark.asyncio
async def test_remove_profile_not_removed_if_wallet_type_not_askar_profile(open_store):
    openStore = open_store
    context = InjectionContext()
    context.settings = {"multitenant.wallet_type": "basic"}
    askar_profile = await AskarProfile.create(openStore, context)

    await askar_profile.remove()

    openStore.store.remove_profile.assert_not_called()


@pytest.mark.asyncio
async def test_profile_manager_transaction():
    profile = "profileId"

    with mock.patch("acapy_agent.askar.profile.AskarProfile") as AskarProfile:
        askar_profile = await AskarProfile.create(None, True, profile_id=profile)
        askar_profile.profile_id = profile
        askar_profile_transaction = mock.MagicMock()
        askar_profile.store.transaction.return_value = askar_profile_transaction

        transactionProfile = test_module.AskarProfileSession(askar_profile, True)

        assert transactionProfile._opener == askar_profile_transaction
        askar_profile.store.transaction.assert_called_once_with(profile)


@pytest.mark.asyncio
async def test_profile_manager_store():
    config = {
        "test": True,
    }
    context = InjectionContext(
        settings=config,
    )
    await AskarProfileManager().provision(
        context=context,
        config=config,
    )
    await AskarAnonProfileManager().provision(
        context=context,
        config=config,
    )
