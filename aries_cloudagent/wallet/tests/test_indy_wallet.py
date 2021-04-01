import base64
import json
import os

import indy.anoncreds
import indy.crypto
import indy.did
import indy.wallet
import pytest

from asynctest import mock as async_mock, TestCase as AsyncTestCase

from ...core.in_memory import InMemoryProfile
from ...config.injection_context import InjectionContext
from ...core.error import ProfileError, ProfileDuplicateError, ProfileNotFoundError
from ...indy.sdk import wallet_setup as test_setup_module
from ...indy.sdk.profile import IndySdkProfileManager
from ...indy.sdk.wallet_setup import IndyWalletConfig
from ...ledger.endpoint_type import EndpointType
from ...ledger.indy import IndySdkLedgerPool

from .. import indy as test_module
from ..base import BaseWallet
from ..in_memory import InMemoryWallet
from ..indy import IndySdkWallet

from . import test_in_memory_wallet


@pytest.fixture()
async def in_memory_wallet():
    profile = InMemoryProfile.test_profile()
    wallet = InMemoryWallet(profile)
    yield wallet


@pytest.fixture()
async def wallet():
    key = await IndySdkWallet.generate_wallet_key()
    context = InjectionContext()
    context.injector.bind_instance(IndySdkLedgerPool, IndySdkLedgerPool("name"))
    profile = await IndySdkProfileManager().provision(
        context,
        {
            "auto_recreate": True,
            "auto_remove": True,
            "name": "test-wallet",
            "key": key,
            "key_derivation_method": "RAW",  # much slower tests with argon-hashed keys
        },
    )
    async with profile.session() as session:
        yield session.inject(BaseWallet)
    await profile.close()


@pytest.mark.indy
class TestIndySdkWallet(test_in_memory_wallet.TestInMemoryWallet):
    """Apply all InMemoryWallet tests against IndySdkWallet"""

    @pytest.mark.asyncio
    async def test_rotate_did_keypair_x(self, wallet):
        info = await wallet.create_local_did(self.test_seed, self.test_did)

        with async_mock.patch.object(
            indy.did, "replace_keys_start", async_mock.CoroutineMock()
        ) as mock_repl_start:
            mock_repl_start.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.rotate_did_keypair_start(self.test_did)
            assert "outlier" in str(excinfo.value)

        with async_mock.patch.object(
            indy.did, "replace_keys_apply", async_mock.CoroutineMock()
        ) as mock_repl_apply:
            mock_repl_apply.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.rotate_did_keypair_apply(self.test_did)
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_signing_key_x(self, wallet):
        with async_mock.patch.object(
            indy.crypto, "create_key", async_mock.CoroutineMock()
        ) as mock_create_key:
            mock_create_key.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.create_signing_key()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_local_did_x(self, wallet):
        with async_mock.patch.object(
            indy.did, "create_and_store_my_did", async_mock.CoroutineMock()
        ) as mock_create:
            mock_create.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.create_local_did()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_set_did_endpoint_ledger(self, wallet):
        mock_ledger = async_mock.MagicMock(
            read_only=False, update_endpoint_for_did=async_mock.CoroutineMock()
        )
        info_pub = await wallet.create_public_did()
        await wallet.set_did_endpoint(info_pub.did, "http://1.2.3.4:8021", mock_ledger)
        mock_ledger.update_endpoint_for_did.assert_called_once_with(
            info_pub.did, "http://1.2.3.4:8021", EndpointType.ENDPOINT
        )
        info_pub2 = await wallet.get_public_did()
        assert info_pub2.metadata["endpoint"] == "http://1.2.3.4:8021"

        with pytest.raises(test_module.LedgerConfigError) as excinfo:
            await wallet.set_did_endpoint(info_pub.did, "http://1.2.3.4:8021", None)
        assert "No ledger available" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_set_did_endpoint_readonly_ledger(self, wallet):
        mock_ledger = async_mock.MagicMock(
            read_only=True, update_endpoint_for_did=async_mock.CoroutineMock()
        )
        info_pub = await wallet.create_public_did()
        await wallet.set_did_endpoint(info_pub.did, "http://1.2.3.4:8021", mock_ledger)
        mock_ledger.update_endpoint_for_did.assert_not_called()
        info_pub2 = await wallet.get_public_did()
        assert info_pub2.metadata["endpoint"] == "http://1.2.3.4:8021"

        with pytest.raises(test_module.LedgerConfigError) as excinfo:
            await wallet.set_did_endpoint(info_pub.did, "http://1.2.3.4:8021", None)
        assert "No ledger available" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_get_signing_key_x(self, wallet):
        with async_mock.patch.object(
            indy.crypto, "get_key_metadata", async_mock.CoroutineMock()
        ) as mock_signing:
            mock_signing.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.get_signing_key(None)
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_get_local_did_x(self, wallet):
        with async_mock.patch.object(
            indy.did, "get_my_did_with_meta", async_mock.CoroutineMock()
        ) as mock_my:
            mock_my.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.get_local_did(None)
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_replace_local_did_metadata_x(self, wallet):
        info = await wallet.create_local_did(
            self.test_seed, self.test_did, None, self.test_metadata
        )
        assert info.did == self.test_did
        assert info.verkey == self.test_verkey
        assert info.metadata == self.test_metadata

        with async_mock.patch.object(
            indy.did, "set_did_metadata", async_mock.CoroutineMock()
        ) as mock_set_did_metadata:
            mock_set_did_metadata.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.replace_local_did_metadata(info.did, info.metadata)
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_verify_message_x(self, wallet):
        with async_mock.patch.object(
            indy.crypto, "crypto_verify", async_mock.CoroutineMock()
        ) as mock_verify:
            mock_verify.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.verify_message(
                    b"hello world", b"signature", self.test_verkey
                )
            assert "outlier" in str(excinfo.value)

            mock_verify.side_effect = test_module.IndyError(  # plain wrong
                test_module.ErrorCode.CommonInvalidStructure
            )
            assert not await wallet.verify_message(
                b"hello world", b"signature", self.test_verkey
            )

    @pytest.mark.asyncio
    async def test_pack_message_x(self, wallet):
        with async_mock.patch.object(
            indy.crypto, "pack_message", async_mock.CoroutineMock()
        ) as mock_pack:
            mock_pack.side_effect = test_module.IndyError(  # outlier
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            with pytest.raises(test_module.WalletError) as excinfo:
                await wallet.pack_message(
                    b"hello world",
                    [
                        self.test_verkey,
                    ],
                )
            assert "outlier" in str(excinfo.value)


@pytest.mark.indy
class TestWalletCompat:
    """ Tests for wallet compatibility."""

    test_seed = "testseed000000000000000000000001"
    test_did = "55GkHamhTU1ZbTbV2ab9DE"
    test_verkey = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    test_message = "test message"

    @pytest.mark.asyncio
    async def test_compare_pack_unpack(self, in_memory_wallet, wallet):
        """
        Ensure that python-based pack/unpack is compatible with indy-sdk implementation
        """
        await in_memory_wallet.create_local_did(self.test_seed)
        py_packed = await in_memory_wallet.pack_message(
            self.test_message, [self.test_verkey], self.test_verkey
        )

        await wallet.create_local_did(self.test_seed)
        packed = await wallet.pack_message(
            self.test_message, [self.test_verkey], self.test_verkey
        )

        py_unpacked, from_vk, to_vk = await in_memory_wallet.unpack_message(packed)
        assert self.test_message == py_unpacked

        unpacked, from_vk, to_vk = await wallet.unpack_message(py_packed)
        assert self.test_message == unpacked

    @pytest.mark.asyncio
    async def test_mock_coverage(self):
        """
        Coverage through mock framework.
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            fake_wallet = IndyWalletConfig(
                {
                    "auto_recreate": True,
                    "auto_remove": False,
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            assert fake_wallet.wallet_access
            opened = await fake_wallet.create_wallet()
            await opened.close()
            await fake_wallet.remove_wallet()

    @pytest.mark.asyncio
    async def test_mock_coverage_wallet_exists_x(self):
        """
        Coverage through mock framework: raise on creation of existing wallet
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_create.side_effect = test_module.IndyError(
                test_module.ErrorCode.WalletAlreadyExistsError
            )
            fake_wallet = IndyWalletConfig(
                {
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            with pytest.raises(ProfileDuplicateError) as excinfo:
                await fake_wallet.create_wallet()

    @pytest.mark.asyncio
    async def test_mock_coverage_wallet_create_x(self):
        """
        Coverage through mock framework: raise on creation outlier
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_create.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            fake_wallet = IndyWalletConfig(
                {
                    "auto_recreate": True,
                    "auto_remove": True,
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            with pytest.raises(ProfileError) as excinfo:
                await fake_wallet.create_wallet()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_mock_coverage_remove_x(self):
        """
        Coverage through mock framework: exception on removal.
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_delete.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            fake_wallet = IndyWalletConfig(
                {
                    "auto_recreate": False,
                    "auto_remove": False,
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            assert fake_wallet.wallet_access
            opened = await fake_wallet.create_wallet()
            await opened.close()
            with pytest.raises(ProfileError) as excinfo:
                await fake_wallet.remove_wallet()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_mock_coverage_not_found_after_creation(self):
        """
        Coverage through mock framework: missing created wallet.
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_open.side_effect = test_module.IndyError(
                test_module.ErrorCode.WalletNotFoundError, {"message": "outlier"}
            )
            fake_wallet = IndyWalletConfig(
                {
                    "auto_recreate": True,
                    "auto_remove": True,
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            with pytest.raises(ProfileError) as excinfo:
                await fake_wallet.create_wallet()
            assert "not found" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_mock_coverage_open_not_found(self):
        """
        Coverage through mock framework: missing wallet on open.
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_open.side_effect = test_module.IndyError(
                test_module.ErrorCode.WalletNotFoundError, {"message": "outlier"}
            )
            fake_wallet = IndyWalletConfig(
                {
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            with pytest.raises(ProfileNotFoundError) as excinfo:
                await fake_wallet.open_wallet()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_mock_coverage_open_indy_already_open_x(self):
        """
        Coverage through mock framework: indy thinks wallet is open, aca-py does not.
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_open.side_effect = test_module.IndyError(
                test_module.ErrorCode.WalletAlreadyOpenedError, {"message": "outlier"}
            )
            fake_wallet = IndyWalletConfig(
                {
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            with pytest.raises(ProfileError) as excinfo:
                await fake_wallet.open_wallet()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_mock_coverage_open_x(self):
        """
        Coverage through mock framework: outlier on wallet open.
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_open.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            fake_wallet = IndyWalletConfig(
                {
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            with pytest.raises(ProfileError) as excinfo:
                await fake_wallet.open_wallet()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_mock_coverage_open_master_secret_x(self):
        """
        Coverage through mock framework: outlier on master secret creation
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_master.side_effect = test_module.IndyError(
                test_module.ErrorCode.CommonIOError, {"message": "outlier"}
            )
            fake_wallet = IndyWalletConfig(
                {
                    "auto_recreate": True,
                    "auto_remove": True,
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            with pytest.raises(ProfileError) as excinfo:
                await fake_wallet.create_wallet()
            assert "outlier" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_mock_coverage_open_master_secret_exists(self):
        """
        Coverage through mock framework: open, master secret exists (OK).
        """
        wallet_key = await IndySdkWallet.generate_wallet_key()
        storage_config_json = json.dumps({"url": "dummy"})
        storage_creds_json = json.dumps(
            {
                "account": "postgres",
                "password": "mysecretpassword",
                "admin_account": "postgres",
                "admin_password": "mysecretpassword",
            },
        )
        with async_mock.patch.object(
            test_setup_module,
            "load_postgres_plugin",
            async_mock.MagicMock(),
        ) as mock_load, async_mock.patch.object(
            indy.wallet, "create_wallet", async_mock.CoroutineMock()
        ) as mock_create, async_mock.patch.object(
            indy.wallet, "open_wallet", async_mock.CoroutineMock()
        ) as mock_open, async_mock.patch.object(
            indy.anoncreds, "prover_create_master_secret", async_mock.CoroutineMock()
        ) as mock_master, async_mock.patch.object(
            indy.wallet, "close_wallet", async_mock.CoroutineMock()
        ) as mock_close, async_mock.patch.object(
            indy.wallet, "delete_wallet", async_mock.CoroutineMock()
        ) as mock_delete:
            mock_master.side_effect = test_module.IndyError(
                test_module.ErrorCode.AnoncredsMasterSecretDuplicateNameError
            )
            fake_wallet = IndyWalletConfig(
                {
                    "auto_recreate": True,
                    "auto_remove": True,
                    "name": "test_pg_wallet",
                    "key": wallet_key,
                    "key_derivation_method": "RAW",
                    "storage_type": "postgres_storage",
                    "storage_config": storage_config_json,
                    "storage_creds": storage_creds_json,
                }
            )
            mock_load.assert_called_once_with(storage_config_json, storage_creds_json)
            assert fake_wallet.wallet_access
            opened = await fake_wallet.create_wallet()
            assert opened.master_secret_id == fake_wallet.name
            await opened.close()
            await fake_wallet.remove_wallet()

    # TODO get these to run in docker ci/cd
    @pytest.mark.asyncio
    @pytest.mark.postgres
    async def test_postgres_wallet_works(self):
        """
        Ensure that postgres wallet operations work (create and open wallet, create did, drop wallet)
        """
        postgres_url = os.environ.get("POSTGRES_URL")
        if not postgres_url:
            pytest.fail("POSTGRES_URL not configured")

        wallet_key = await IndySdkWallet.generate_wallet_key()
        postgres_wallet = IndyWalletConfig(
            {
                "auto_recreate": True,
                "auto_remove": True,
                "name": "test_pg_wallet",
                "key": wallet_key,
                "key_derivation_method": "RAW",
                "storage_type": "postgres_storage",
                "storage_config": '{"url":"' + postgres_url + '"}',
                "storage_creds": '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}',
            }
        )
        assert postgres_wallet.wallet_access
        opened = await postgres_wallet.create_wallet()
        wallet = IndySdkWallet(opened)

        await wallet.create_local_did(self.test_seed)
        py_packed = await wallet.pack_message(
            self.test_message, [self.test_verkey], self.test_verkey
        )

        await wallet.close()
        await postgres_wallet.remove_wallet()

    # TODO get these to run in docker ci/cd
    @pytest.mark.asyncio
    @pytest.mark.postgres
    async def test_postgres_wallet_scheme_works(self):
        """
        Ensure that postgres wallet operations work (create and open wallet, create did, drop wallet)
        """
        postgres_url = os.environ.get("POSTGRES_URL")
        if not postgres_url:
            pytest.fail("POSTGRES_URL not configured")

        wallet_key = await IndySdkWallet.generate_wallet_key()
        postgres_wallet = IndyWalletConfig(
            {
                "auto_recreate": True,
                "auto_remove": True,
                "name": "test_pg_wallet",
                "key": wallet_key,
                "key_derivation_method": "RAW",
                "storage_type": "postgres_storage",
                "storage_config": '{"url":"'
                + postgres_url
                + '", "wallet_scheme":"MultiWalletSingleTable"}',
                "storage_creds": '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}',
            }
        )
        assert postgres_wallet.wallet_access
        opened = await postgres_wallet.create_wallet()

        with pytest.raises(ProfileError) as excinfo:
            await postgres_wallet.create_wallet()
        assert "Wallet was not removed" in str(excinfo.value)

        wallet = IndySdkWallet(opened)
        await wallet.create_local_did(self.test_seed)
        py_packed = await wallet.pack_message(
            self.test_message, [self.test_verkey], self.test_verkey
        )

        await wallet.close()
        await postgres_wallet.remove_wallet()

    # TODO get these to run in docker ci/cd
    @pytest.mark.asyncio
    @pytest.mark.postgres
    async def test_postgres_wallet_scheme2_works(self):
        """
        Ensure that postgres wallet operations work (create and open wallet, create did, drop wallet)
        """
        postgres_url = os.environ.get("POSTGRES_URL")
        if not postgres_url:
            pytest.fail("POSTGRES_URL not configured")

        wallet_key = await IndySdkWallet.generate_wallet_key()
        postgres_wallet = IndyWalletConfig(
            {
                "auto_recreate": True,
                "auto_remove": True,
                "name": "test_pg_wallet",
                "key": wallet_key,
                "key_derivation_method": "RAW",
                "storage_type": "postgres_storage",
                "storage_config": '{"url":"'
                + postgres_url
                + '", "wallet_scheme":"MultiWalletSingleTableSharedPool"}',
                "storage_creds": '{"account":"postgres","password":"mysecretpassword","admin_account":"postgres","admin_password":"mysecretpassword"}',
            }
        )
        opened = await postgres_wallet.create_wallet()
        wallet = IndySdkWallet(opened)

        await wallet.create_local_did(self.test_seed)
        py_packed = await wallet.pack_message(
            self.test_message, [self.test_verkey], self.test_verkey
        )

        await wallet.close()
        await postgres_wallet.remove_wallet()
