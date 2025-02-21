import json
import os
from unittest import IsolatedAsyncioTestCase

import pytest

from ...askar.profile import AskarProfileManager
from ...config.injection_context import InjectionContext
from ...tests import mock
from ...wallet.askar import AskarWallet
from .. import askar as test_module
from ..askar import AskarStorage
from ..base import BaseStorage
from ..error import StorageError, StorageSearchError
from ..record import StorageRecord


@pytest.fixture()
async def store():
    context = InjectionContext()
    profile = await AskarProfileManager().provision(
        context,
        {
            # "auto_recreate": True,
            # "auto_remove": True,
            "name": ":memory:",
            "key": await AskarProfileManager.generate_store_key(),
            "key_derivation_method": "RAW",  # much faster than using argon-hashed keys
        },
    )
    async with profile.session() as session:
        yield session.inject(BaseStorage)
    del session
    # this will block indefinitely if session or profile references remain
    # await profile.close()


# TODO: Ignore "Undefined name `indy`" errors; these tests should be revisited
# ruff: noqa: F821


@pytest.mark.askar
class TestAskarStorage:
    """Tests for Askar storage."""

    @pytest.mark.skip
    @pytest.mark.asyncio
    async def test_record(self):
        with (
            mock.patch.object(
                indy.wallet, "create_wallet", mock.CoroutineMock()
            ) as mock_create,
            mock.patch.object(
                indy.wallet, "open_wallet", mock.CoroutineMock()
            ) as mock_open,
            mock.patch.object(
                indy.anoncreds, "prover_create_master_secret", mock.CoroutineMock()
            ) as mock_master,
            mock.patch.object(
                indy.wallet, "close_wallet", mock.CoroutineMock()
            ) as mock_close,
            mock.patch.object(
                indy.wallet, "delete_wallet", mock.CoroutineMock()
            ) as mock_delete,
        ):
            fake_wallet = AskarWallet(
                {
                    "auto_create": True,
                    "auto_remove": True,
                    "name": "test_pg_wallet",
                    "key": await AskarWallet.generate_wallet_key(),
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": json.dumps({"url": "dummy"}),
                    "storage_creds": json.dumps(
                        {
                            "account": "postgres",
                            "password": "mysecretpassword",
                            "admin_account": "postgres",
                            "admin_password": "mysecretpassword",
                        }
                    ),
                }
            )
            await fake_wallet.open()
            storage = AskarStorage(fake_wallet)

            for record_x in [
                None,
                StorageRecord(
                    type="connection",
                    value=json.dumps(
                        {
                            "initiator": "self",
                            "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                            "state": "invitation",
                            "routing_state": "none",
                            "error_msg": None,
                            "their_label": None,
                            "created_at": "2019-05-14 21:58:24.143260+00:00",
                            "updated_at": "2019-05-14 21:58:24.143260+00:00",
                        }
                    ),
                    tags={
                        "initiator": "self",
                        "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                        "state": "invitation",
                        "routing_state": "none",
                    },
                    id=None,
                ),
                StorageRecord(
                    type=None,
                    value=json.dumps(
                        {
                            "initiator": "self",
                            "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                            "state": "invitation",
                            "routing_state": "none",
                            "error_msg": None,
                            "their_label": None,
                            "created_at": "2019-05-14 21:58:24.143260+00:00",
                            "updated_at": "2019-05-14 21:58:24.143260+00:00",
                        }
                    ),
                    tags={
                        "initiator": "self",
                        "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                        "state": "invitation",
                        "routing_state": "none",
                    },
                    id="f96f76ec-0e9b-4f32-8237-f4219e6cf0c7",
                ),
                StorageRecord(
                    type="connection",
                    value=None,
                    tags={
                        "initiator": "self",
                        "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                        "state": "invitation",
                        "routing_state": "none",
                    },
                    id="f96f76ec-0e9b-4f32-8237-f4219e6cf0c7",
                ),
            ]:
                with pytest.raises(StorageError):
                    await storage.add_record(record_x)

            with pytest.raises(StorageError):
                await storage.get_record(None, "dummy-id")
            with pytest.raises(StorageError):
                await storage.get_record("connection", None)

            with mock.patch.object(
                test_module.non_secrets, "get_wallet_record", mock.CoroutineMock()
            ) as mock_get_record:
                mock_get_record.side_effect = test_module.IndyError(
                    test_module.ErrorCode.CommonInvalidStructure
                )
                with pytest.raises(test_module.StorageError):
                    await storage.get_record("connection", "dummy-id")

            with (
                mock.patch.object(
                    test_module.non_secrets,
                    "update_wallet_record_value",
                    mock.CoroutineMock(),
                ) as mock_update_value,
                mock.patch.object(
                    test_module.non_secrets,
                    "update_wallet_record_tags",
                    mock.CoroutineMock(),
                ) as mock_update_tags,
                mock.patch.object(
                    test_module.non_secrets,
                    "delete_wallet_record",
                    mock.CoroutineMock(),
                ) as mock_delete,
            ):
                mock_update_value.side_effect = test_module.IndyError(
                    test_module.ErrorCode.CommonInvalidStructure
                )
                mock_update_tags.side_effect = test_module.IndyError(
                    test_module.ErrorCode.CommonInvalidStructure
                )
                mock_delete.side_effect = test_module.IndyError(
                    test_module.ErrorCode.CommonInvalidStructure
                )

                rec = StorageRecord(
                    type="connection",
                    value=json.dumps(
                        {
                            "initiator": "self",
                            "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                            "state": "invitation",
                            "routing_state": "none",
                            "error_msg": None,
                            "their_label": None,
                            "created_at": "2019-05-14 21:58:24.143260+00:00",
                            "updated_at": "2019-05-14 21:58:24.143260+00:00",
                        }
                    ),
                    tags={
                        "initiator": "self",
                        "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                        "state": "invitation",
                        "routing_state": "none",
                    },
                    id="f96f76ec-0e9b-4f32-8237-f4219e6cf0c7",
                )

                with pytest.raises(test_module.StorageError):
                    await storage.update_record(rec, "dummy-value", {"tag": "tag"})

                with pytest.raises(test_module.StorageError):
                    await storage.delete_record(rec)

    @pytest.mark.skip
    @pytest.mark.asyncio
    async def test_storage_search_x(self):
        with (
            mock.patch.object(
                indy.wallet, "create_wallet", mock.CoroutineMock()
            ) as mock_create,
            mock.patch.object(
                indy.wallet, "open_wallet", mock.CoroutineMock()
            ) as mock_open,
            mock.patch.object(
                indy.anoncreds, "prover_create_master_secret", mock.CoroutineMock()
            ) as mock_master,
            mock.patch.object(
                indy.wallet, "close_wallet", mock.CoroutineMock()
            ) as mock_close,
            mock.patch.object(
                indy.wallet, "delete_wallet", mock.CoroutineMock()
            ) as mock_delete,
        ):
            fake_wallet = AskarWallet(
                {
                    "auto_create": True,
                    "auto_remove": True,
                    "name": "test_pg_wallet",
                    "key": await AskarWallet.generate_wallet_key(),
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": json.dumps({"url": "dummy"}),
                    "storage_creds": json.dumps(
                        {
                            "account": "postgres",
                            "password": "mysecretpassword",
                            "admin_account": "postgres",
                            "admin_password": "mysecretpassword",
                        }
                    ),
                }
            )
            await fake_wallet.open()
            storage = AskarStorage(fake_wallet)

            search = storage.search_records("connection")
            with pytest.raises(StorageSearchError):
                await search.fetch(10)

            with (
                mock.patch.object(
                    indy.non_secrets, "open_wallet_search", mock.CoroutineMock()
                ) as mock_indy_open_search,
                mock.patch.object(
                    indy.non_secrets, "close_wallet_search", mock.CoroutineMock()
                ) as mock_indy_close_search,
            ):
                mock_indy_open_search.side_effect = test_module.IndyError("no open")
                search = storage.search_records("connection")
                with pytest.raises(StorageSearchError):
                    await search.open()
                await search.close()

            with (
                mock.patch.object(
                    indy.non_secrets, "open_wallet_search", mock.CoroutineMock()
                ) as mock_indy_open_search,
                mock.patch.object(
                    indy.non_secrets,
                    "fetch_wallet_search_next_records",
                    mock.CoroutineMock(),
                ) as mock_indy_fetch,
                mock.patch.object(
                    indy.non_secrets, "close_wallet_search", mock.CoroutineMock()
                ) as mock_indy_close_search,
            ):
                mock_indy_fetch.side_effect = test_module.IndyError("no fetch")
                search = storage.search_records("connection")
                await search.open()
                with pytest.raises(StorageSearchError):
                    await search.fetch(10)
                await search.close()

            with (
                mock.patch.object(
                    indy.non_secrets, "open_wallet_search", mock.CoroutineMock()
                ) as mock_indy_open_search,
                mock.patch.object(
                    indy.non_secrets, "close_wallet_search", mock.CoroutineMock()
                ) as mock_indy_close_search,
            ):
                mock_indy_close_search.side_effect = test_module.IndyError("no close")
                search = storage.search_records("connection")
                await search.open()
                with pytest.raises(StorageSearchError):
                    await search.close()

    # TODO get these to run in docker ci/cd
    @pytest.mark.skip
    @pytest.mark.asyncio
    @pytest.mark.postgres
    async def test_postgres_wallet_storage_works(self):
        """
        Ensure that postgres wallet operations work (create and open wallet, store and search, drop wallet)
        """
        postgres_url = os.environ.get("POSTGRES_URL")
        if not postgres_url:
            pytest.fail("POSTGRES_URL not configured")

        wallet_key = await AskarWallet.generate_wallet_key()
        postgres_wallet = AskarWallet(
            {
                "auto_create": False,
                "auto_remove": False,
                "name": "test_pg_wallet",
                "key": wallet_key,
                "key_derivation_method": "RAW",
                "storage_type": "postgres_storage",
                "storage_config": '{"url":"' + postgres_url + '", "max_connections":5}',
                "storage_creds": '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}',
            }
        )
        await postgres_wallet.create()
        await postgres_wallet.open()

        storage = AskarStorage(postgres_wallet)

        # add and then fetch a record
        record = StorageRecord(
            type="connection",
            value=json.dumps(
                {
                    "initiator": "self",
                    "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                    "state": "invitation",
                    "routing_state": "none",
                    "error_msg": None,
                    "their_label": None,
                    "created_at": "2019-05-14 21:58:24.143260+00:00",
                    "updated_at": "2019-05-14 21:58:24.143260+00:00",
                }
            ),
            tags={
                "initiator": "self",
                "invitation_key": "9XgL7Y4TBTJyVJdomT6axZGUFg9npxcrXnRT4CG8fWYg",
                "state": "invitation",
                "routing_state": "none",
            },
            id="f96f76ec-0e9b-4f32-8237-f4219e6cf0c7",
        )
        await storage.add_record(record)
        g_rec = await storage.get_record(record.type, record.id)

        # now try search
        search = None
        try:
            search = storage.search_records("connection")
            await search.open()
            records = await search.fetch(10)
        finally:
            if search:
                await search.close()

        await postgres_wallet.close()
        await postgres_wallet.remove()


class TestAskarStorageSearchSession(IsolatedAsyncioTestCase):
    async def test_askar_storage_search_session(self):
        profile = "profileId"

        with mock.patch("acapy_agent.storage.askar.AskarProfile") as AskarProfile:
            askar_profile = await AskarProfile.create(None, True)
            askar_profile_scan = mock.MagicMock()
            askar_profile.store.scan.return_value = askar_profile_scan
            askar_profile.settings.get.return_value = profile

            storageSearchSession = test_module.AskarStorageSearchSession(
                askar_profile, "filter", "tagQuery"
            )
            await storageSearchSession._open()

            assert storageSearchSession._scan == askar_profile_scan
            askar_profile.settings.get.assert_called_once_with("wallet.askar_profile")
            askar_profile.store.scan.assert_called_once_with(
                category="filter",
                tag_filter="tagQuery",
                limit=None,
                offset=None,
                profile=profile,
            )
