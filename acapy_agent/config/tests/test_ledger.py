import sys
from unittest import IsolatedAsyncioTestCase

import pytest

from ...askar.profile import AskarProfileSession
from ...ledger.base import BaseLedger
from ...ledger.error import LedgerError
from ...tests import mock
from ...utils.testing import create_test_profile
from .. import argparse
from .. import ledger as test_module

TEST_DID = "55GkHamhTU1ZbTbV2ab9DE"
TEST_GENESIS = "GENESIS"


class TestLedgerConfig(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.profile = await create_test_profile(
            settings={
                "wallet-type": "askar-anoncreds",
                "tails_server_base_url": "http://tails-server.com",
            }
        )

    async def test_fetch_genesis_transactions(self):
        with mock.patch.object(test_module, "fetch", mock.CoroutineMock()):
            await test_module.fetch_genesis_transactions("http://1.2.3.4:9000/genesis")

    async def test_fetch_genesis_transactions_x(self):
        with mock.patch.object(
            test_module, "fetch", mock.CoroutineMock(return_value=TEST_GENESIS)
        ) as mock_fetch:
            mock_fetch.side_effect = test_module.FetchError("404 Not Found")
            with self.assertRaises(test_module.ConfigError):
                await test_module.fetch_genesis_transactions(
                    "http://1.2.3.4:9000/genesis"
                )

    async def test_get_genesis_url(self):
        settings = {
            "ledger.genesis_url": "00000000000000000000000000000000",
        }
        with mock.patch.object(
            test_module,
            "fetch_genesis_transactions",
            mock.CoroutineMock(return_value=TEST_GENESIS),
        ):
            await test_module.get_genesis_transactions(settings)
        self.assertEqual(settings["ledger.genesis_transactions"], TEST_GENESIS)

    async def test_get_genesis_file(self):
        settings = {
            "ledger.genesis_file": "/tmp/genesis/path",
        }
        with mock.patch("builtins.open", mock.MagicMock()) as mock_open:
            mock_open.return_value = mock.MagicMock(
                __enter__=mock.MagicMock(
                    return_value=mock.MagicMock(
                        read=mock.MagicMock(return_value=TEST_GENESIS)
                    )
                )
            )
            await test_module.get_genesis_transactions(settings)
        self.assertEqual(settings["ledger.genesis_transactions"], TEST_GENESIS)

    async def test_get_genesis_file_io_x(self):
        settings = {
            "ledger.genesis_file": "/tmp/genesis/path",
        }

        with mock.patch("builtins.open", mock.MagicMock()) as mock_open:
            mock_open.side_effect = IOError("no read permission")
            with self.assertRaises(test_module.ConfigError):
                await test_module.get_genesis_transactions(settings)

    async def test_ledger_config_no_taa_accept(self):
        settings = {
            "ledger.genesis_transactions": TEST_GENESIS,
            "default_endpoint": "http://1.2.3.4:8051",
        }
        mock_ledger = mock.MagicMock(BaseLedger, autospec=True)
        mock_ledger.get_txn_author_agreement = mock.CoroutineMock(
            return_value={
                "taa_required": True,
                "taa_record": {"digest": b"ffffffffffffffffffffffffffffffffffffffff"},
            }
        )
        mock_ledger.get_latest_txn_author_acceptance = mock.CoroutineMock(
            return_value={"digest": b"1234567890123456789012345678901234567890"}
        )

        mock_ledger.read_only = False

        self.profile = await create_test_profile(settings=settings)

        self.profile.context.injector.bind_instance(BaseLedger, mock_ledger)

        with mock.patch.object(
            test_module, "accept_taa", mock.CoroutineMock()
        ) as mock_accept_taa:
            mock_accept_taa.return_value = False
            assert not await test_module.ledger_config(
                self.profile, TEST_DID, provision=True
            )

    @mock.patch.object(
        AskarProfileSession,
        "inject",
        mock.MagicMock(
            return_value=mock.MagicMock(set_did_endpoint=mock.CoroutineMock())
        ),
    )
    async def test_accept_taa(self):
        settings = {
            "ledger.genesis_transactions": TEST_GENESIS,
        }
        mock_ledger = mock.MagicMock(BaseLedger, autospec=True)
        mock_ledger.get_txn_author_agreement = mock.CoroutineMock(
            return_value={
                "taa_required": True,
                "taa_record": {"digest": b"ffffffffffffffffffffffffffffffffffffffff"},
            }
        )
        mock_ledger.get_latest_txn_author_acceptance = mock.CoroutineMock(
            return_value={"digest": b"1234567890123456789012345678901234567890"}
        )
        mock_ledger.update_endpoint_for_did = mock.CoroutineMock()
        mock_ledger.read_only = False

        self.profile = await create_test_profile(settings=settings)
        self.profile.context.injector.bind_instance(BaseLedger, mock_ledger)

        with mock.patch.object(
            test_module, "accept_taa", mock.CoroutineMock()
        ) as mock_accept_taa:
            mock_accept_taa.return_value = True
            await test_module.ledger_config(self.profile, TEST_DID, provision=True)
            mock_accept_taa.assert_awaited_once()

    @mock.patch.object(
        AskarProfileSession,
        "inject",
        mock.MagicMock(
            return_value=mock.MagicMock(
                set_did_endpoint=mock.CoroutineMock(
                    side_effect=LedgerError(
                        "Error cannot update endpoint when ledger is in read only mode"
                    )
                )
            )
        ),
    )
    async def test_ledger_config_read_only_skip_taa_accept(self):
        settings = {
            "ledger.genesis_transactions": TEST_GENESIS,
        }

        mock_ledger = mock.MagicMock(BaseLedger, autospec=True)
        mock_ledger.get_txn_author_agreement = mock.CoroutineMock()
        mock_ledger.get_latest_txn_author_acceptance = mock.CoroutineMock()
        mock_ledger.read_only = True

        self.profile = await create_test_profile(settings=settings)
        self.profile.context.injector.bind_instance(BaseLedger, mock_ledger)

        with mock.patch.object(test_module, "accept_taa", mock.CoroutineMock()):
            with self.assertRaises(test_module.ConfigError) as x_context:
                await test_module.ledger_config(self.profile, TEST_DID, provision=True)
            assert "ledger is in read only mode" in str(x_context.exception)
            mock_ledger.get_txn_author_agreement.assert_not_called()
            mock_ledger.get_latest_txn_author_acceptance.assert_not_called()

    @mock.patch.object(
        AskarProfileSession,
        "inject",
        mock.MagicMock(
            return_value=mock.MagicMock(set_did_endpoint=mock.CoroutineMock())
        ),
    )
    async def test_ledger_config_read_only_skip_profile_endpoint_publish(self):
        settings = {
            "ledger.genesis_url": "00000000000000000000000000000000",
            "profile_endpoint": "http://agent.ca",
        }

        mock_ledger = mock.MagicMock(BaseLedger, autospec=True)
        mock_ledger.get_txn_author_agreement = mock.CoroutineMock()
        mock_ledger.get_latest_txn_author_acceptance = mock.CoroutineMock()
        mock_ledger.read_only = True

        self.profile = await create_test_profile(settings=settings)
        self.profile.context.injector.bind_instance(BaseLedger, mock_ledger)

        with mock.patch.object(test_module, "accept_taa", mock.CoroutineMock()):
            await test_module.ledger_config(self.profile, TEST_DID, provision=True)
            mock_ledger.get_txn_author_agreement.assert_not_called()
            mock_ledger.get_latest_txn_author_acceptance.assert_not_called()
            mock_ledger.update_endpoint_for_did.assert_not_called()

    @mock.patch.object(
        AskarProfileSession,
        "inject",
        mock.MagicMock(
            return_value=mock.MagicMock(set_did_endpoint=mock.CoroutineMock())
        ),
    )
    async def test_ledger_config_read_write_skip_taa_endpoint_publish(self):
        settings = {
            "ledger.genesis_url": "00000000000000000000000000000000",
            "default_endpoint": "http://agent-default.ca",
            "profile_endpoint": "http://agent-profile.ca",
        }
        mock_ledger = mock.MagicMock(BaseLedger, autospec=True)
        mock_ledger.get_txn_author_agreement = mock.CoroutineMock(
            return_value={"taa_required": False}
        )
        mock_ledger.get_latest_txn_author_acceptance = mock.CoroutineMock()
        mock_ledger.read_only = False

        self.profile = await create_test_profile(settings=settings)
        self.profile.context.injector.bind_instance(BaseLedger, mock_ledger)

        with mock.patch.object(test_module, "accept_taa", mock.CoroutineMock()):
            await test_module.ledger_config(
                self.profile,
                public_did=TEST_DID,
                provision=False,
            )
            mock_ledger.get_txn_author_agreement.assert_called_once_with()
            mock_ledger.get_latest_txn_author_acceptance.assert_not_called()
            mock_ledger.update_endpoint_for_did.assert_called_once_with(
                TEST_DID,
                settings["profile_endpoint"],
                test_module.EndpointType.PROFILE,
            )

    async def test_load_multiple_genesis_transactions_from_config_a(self):
        TEST_GENESIS_TXNS = {
            "reqSignature": {},
            "txn": {
                "data": {
                    "data": {
                        "alias": "Node1",
                        "blskey": "4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba",
                        "blskey_pop": "RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1",
                        "client_ip": "192.168.65.3",
                        "client_port": 9702,
                        "node_ip": "192.168.65.3",
                        "node_port": 9701,
                        "services": ["VALIDATOR"],
                    },
                    "dest": "Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv",
                },
                "metadata": {"from": "Th7MpTaRZVRYnPiabds81Y"},
                "type": "0",
            },
            "txnMetadata": {
                "seqNo": 1,
                "txnId": "fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62",
            },
            "ver": "1",
        }
        TEST_MULTIPLE_LEDGER_CONFIG_LIST = [
            {
                "id": "sovrinMain",
                "is_production": True,
                "genesis_transactions": TEST_GENESIS_TXNS,
                "is_write": True,
                "keepalive": 5,
                "read_only": False,
                "socks_proxy": None,
                "pool_name": "sovrinMain",
                "endorser_did": "9QPa6tHvBHttLg6U4xvviv",
                "endorser_alias": "endorser_main",
            },
            {
                "id": "sovrinStaging",
                "is_production": True,
                "genesis_transactions": TEST_GENESIS_TXNS,
                "is_write": False,
                "keepalive": 5,
                "read_only": False,
                "socks_proxy": None,
                "pool_name": "sovrinStaging",
            },
            {
                "id": "sovrinTest",
                "is_production": True,
                "genesis_transactions": TEST_GENESIS_TXNS,
                "is_write": False,
                "keepalive": 5,
                "read_only": False,
                "socks_proxy": None,
                "pool_name": "sovrinTest",
            },
        ]
        settings = {
            "ledger.ledger_config_list": [
                {
                    "id": "sovrinMain",
                    "is_production": True,
                    "is_write": True,
                    "genesis_transactions": TEST_GENESIS_TXNS,
                    "endorser_did": "9QPa6tHvBHttLg6U4xvviv",
                    "endorser_alias": "endorser_main",
                },
                {
                    "id": "sovrinStaging",
                    "is_production": True,
                    "genesis_file": "/home/indy/ledger/sandbox/pool_transactions_genesis",
                },
                {
                    "id": "sovrinTest",
                    "is_production": True,
                    "genesis_url": "http://localhost:9000/genesis",
                },
            ],
        }
        with (
            mock.patch.object(
                test_module,
                "fetch_genesis_transactions",
                mock.CoroutineMock(return_value=TEST_GENESIS_TXNS),
            ),
            mock.patch("builtins.open", mock.MagicMock()) as mock_open,
        ):
            mock_open.return_value = mock.MagicMock(
                __enter__=mock.MagicMock(
                    return_value=mock.MagicMock(
                        read=mock.MagicMock(return_value=TEST_GENESIS_TXNS)
                    )
                )
            )
            await test_module.load_multiple_genesis_transactions_from_config(settings)
        self.assertEqual(
            settings["ledger.ledger_config_list"], TEST_MULTIPLE_LEDGER_CONFIG_LIST
        )

    async def test_load_multiple_genesis_transactions_from_config_b(self):
        TEST_GENESIS_TXNS = {
            "reqSignature": {},
            "txn": {
                "data": {
                    "data": {
                        "alias": "Node1",
                        "blskey": "4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba",
                        "blskey_pop": "RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1",
                        "client_ip": "192.168.65.3",
                        "client_port": 9702,
                        "node_ip": "192.168.65.3",
                        "node_port": 9701,
                        "services": ["VALIDATOR"],
                    },
                    "dest": "Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv",
                },
                "metadata": {"from": "Th7MpTaRZVRYnPiabds81Y"},
                "type": "0",
            },
            "txnMetadata": {
                "seqNo": 1,
                "txnId": "fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62",
            },
            "ver": "1",
        }
        TEST_MULTIPLE_LEDGER_CONFIG_LIST = [
            {
                "id": "sovrinMain",
                "is_production": True,
                "genesis_transactions": TEST_GENESIS_TXNS,
                "is_write": False,
                "keepalive": 5,
                "read_only": False,
                "socks_proxy": None,
                "pool_name": "sovrinMain",
            },
            {
                "id": "sovrinStaging",
                "is_production": True,
                "genesis_transactions": TEST_GENESIS_TXNS,
                "is_write": False,
                "keepalive": 5,
                "read_only": False,
                "socks_proxy": None,
                "pool_name": "sovrinStaging",
            },
            {
                "id": "sovrinTest",
                "is_production": True,
                "genesis_transactions": TEST_GENESIS_TXNS,
                "is_write": False,
                "keepalive": 5,
                "read_only": False,
                "socks_proxy": None,
                "pool_name": "sovrinTest",
            },
        ]
        settings = {
            "ledger.ledger_config_list": [
                {
                    "id": "sovrinMain",
                    "is_production": True,
                    "genesis_transactions": TEST_GENESIS_TXNS,
                },
                {
                    "id": "sovrinStaging",
                    "is_production": True,
                    "genesis_file": "/home/indy/ledger/sandbox/pool_transactions_genesis",
                },
                {
                    "id": "sovrinTest",
                    "is_production": True,
                    "genesis_url": "http://localhost:9001/genesis",
                },
            ],
            "ledger.genesis_url": "http://localhost:9000/genesis",
        }
        with (
            mock.patch.object(
                test_module,
                "fetch_genesis_transactions",
                mock.CoroutineMock(return_value=TEST_GENESIS_TXNS),
            ),
            mock.patch("builtins.open", mock.MagicMock()) as mock_open,
        ):
            mock_open.return_value = mock.MagicMock(
                __enter__=mock.MagicMock(
                    return_value=mock.MagicMock(
                        read=mock.MagicMock(return_value=TEST_GENESIS_TXNS)
                    )
                )
            )
            await test_module.load_multiple_genesis_transactions_from_config(settings)
        self.assertEqual(
            settings["ledger.ledger_config_list"], TEST_MULTIPLE_LEDGER_CONFIG_LIST
        )

    async def test_load_multiple_genesis_transactions_config_error_a(self):
        TEST_GENESIS_TXNS = {
            "reqSignature": {},
            "txn": {
                "data": {
                    "data": {
                        "alias": "Node1",
                        "blskey": "4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba",
                        "blskey_pop": "RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1",
                        "client_ip": "192.168.65.3",
                        "client_port": 9702,
                        "node_ip": "192.168.65.3",
                        "node_port": 9701,
                        "services": ["VALIDATOR"],
                    },
                    "dest": "Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv",
                },
                "metadata": {"from": "Th7MpTaRZVRYnPiabds81Y"},
                "type": "0",
            },
            "txnMetadata": {
                "seqNo": 1,
                "txnId": "fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62",
            },
            "ver": "1",
        }
        settings = {
            "ledger.ledger_config_list": [
                {
                    "id": "sovrinMain",
                    "is_production": True,
                    "genesis_transactions": TEST_GENESIS_TXNS,
                },
                {
                    "id": "sovrinStaging",
                    "is_production": True,
                    "genesis_file": "/home/indy/ledger/sandbox/pool_transactions_genesis",
                },
                {
                    "id": "sovrinTest",
                    "is_production": True,
                    "genesis_url": "http://localhost:9001/genesis",
                },
            ],
        }
        with (
            mock.patch.object(
                test_module,
                "fetch_genesis_transactions",
                mock.CoroutineMock(return_value=TEST_GENESIS_TXNS),
            ),
            mock.patch("builtins.open", mock.MagicMock()) as mock_open,
        ):
            mock_open.return_value = mock.MagicMock(
                __enter__=mock.MagicMock(
                    return_value=mock.MagicMock(
                        read=mock.MagicMock(return_value=TEST_GENESIS_TXNS)
                    )
                )
            )
            with self.assertRaises(test_module.ConfigError) as cm:
                await test_module.load_multiple_genesis_transactions_from_config(settings)
            assert "No is_write ledger set" in str(cm.exception)

    async def test_load_multiple_genesis_transactions_multiple_write(self):
        TEST_GENESIS_TXNS = {
            "reqSignature": {},
            "txn": {
                "data": {
                    "data": {
                        "alias": "Node1",
                        "blskey": "4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba",
                        "blskey_pop": "RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1",
                        "client_ip": "192.168.65.3",
                        "client_port": 9702,
                        "node_ip": "192.168.65.3",
                        "node_port": 9701,
                        "services": ["VALIDATOR"],
                    },
                    "dest": "Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv",
                },
                "metadata": {"from": "Th7MpTaRZVRYnPiabds81Y"},
                "type": "0",
            },
            "txnMetadata": {
                "seqNo": 1,
                "txnId": "fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62",
            },
            "ver": "1",
        }
        settings = {
            "ledger.ledger_config_list": [
                {
                    "id": "sovrinMain",
                    "is_production": True,
                    "is_write": True,
                    "genesis_transactions": TEST_GENESIS_TXNS,
                },
                {
                    "id": "sovrinStaging",
                    "is_production": True,
                    "is_write": True,
                    "genesis_file": "/home/indy/ledger/sandbox/pool_transactions_genesis",
                },
                {
                    "id": "sovrinTest",
                    "is_production": True,
                    "genesis_url": "http://localhost:9001/genesis",
                },
            ]
        }
        with (
            mock.patch.object(
                test_module,
                "fetch_genesis_transactions",
                mock.CoroutineMock(return_value=TEST_GENESIS_TXNS),
            ),
            mock.patch("builtins.open", mock.MagicMock()) as mock_open,
        ):
            mock_open.return_value = mock.MagicMock(
                __enter__=mock.MagicMock(
                    return_value=mock.MagicMock(
                        read=mock.MagicMock(return_value=TEST_GENESIS_TXNS)
                    )
                )
            )
            await test_module.load_multiple_genesis_transactions_from_config(settings)

    async def test_load_multiple_genesis_transactions_from_config_io_x(self):
        TEST_GENESIS_TXNS = {
            "reqSignature": {},
            "txn": {
                "data": {
                    "data": {
                        "alias": "Node1",
                        "blskey": "4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba",
                        "blskey_pop": "RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1",
                        "client_ip": "192.168.65.3",
                        "client_port": 9702,
                        "node_ip": "192.168.65.3",
                        "node_port": 9701,
                        "services": ["VALIDATOR"],
                    },
                    "dest": "Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv",
                },
                "metadata": {"from": "Th7MpTaRZVRYnPiabds81Y"},
                "type": "0",
            },
            "txnMetadata": {
                "seqNo": 1,
                "txnId": "fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62",
            },
            "ver": "1",
        }
        settings = {
            "ledger.ledger_config_list": [
                {
                    "id": "sovrinMain",
                    "is_production": True,
                    "genesis_transactions": TEST_GENESIS_TXNS,
                },
                {
                    "id": "sovrinStaging",
                    "is_production": True,
                    "genesis_file": "/home/indy/ledger/sandbox/pool_transactions_genesis",
                },
                {
                    "id": "sovrinTest",
                    "is_production": True,
                    "genesis_url": "http://localhost:9000/genesis",
                },
            ],
        }
        with (
            mock.patch.object(
                test_module,
                "fetch_genesis_transactions",
                mock.CoroutineMock(return_value=TEST_GENESIS_TXNS),
            ),
            mock.patch("builtins.open", mock.MagicMock()) as mock_open,
        ):
            mock_open.side_effect = IOError("no read permission")
            with self.assertRaises(test_module.ConfigError):
                await test_module.load_multiple_genesis_transactions_from_config(settings)

    @mock.patch("sys.stdout")
    async def test_ledger_accept_taa_not_tty_not_accept_config(self, mock_stdout):
        mock_stdout.isatty = mock.MagicMock(return_value=False)
        self.profile = await create_test_profile()

        taa_info = {
            "taa_record": {"version": "1.0", "text": "Agreement"},
            "aml_record": {"aml": ["wallet_agreement", "on_file"]},
        }

        assert not await test_module.accept_taa(
            None, self.profile, taa_info, provision=False
        )

    async def test_ledger_accept_taa_tty(self):
        sys.stdout.isatty = mock.MagicMock(return_value=True)
        self.profile = await create_test_profile()

        taa_info = {
            "taa_record": {"version": "1.0", "text": "Agreement"},
            "aml_record": {"aml": ["wallet_agreement", "on_file"]},
        }

        with (
            mock.patch.object(
                test_module.prompt_toolkit, "prompt", mock.CoroutineMock()
            ) as mock_prompt,
        ):
            mock_prompt.side_effect = EOFError()
            assert not await test_module.accept_taa(
                None, self.profile, taa_info, provision=False
            )

        with (
            mock.patch.object(
                test_module.prompt_toolkit, "prompt", mock.CoroutineMock()
            ) as mock_prompt,
        ):
            mock_prompt.return_value = "x"
            assert not await test_module.accept_taa(
                None, self.profile, taa_info, provision=False
            )

        with (
            mock.patch.object(
                test_module.prompt_toolkit, "prompt", mock.CoroutineMock()
            ) as mock_prompt,
        ):
            mock_ledger = mock.MagicMock(accept_txn_author_agreement=mock.CoroutineMock())
            mock_prompt.return_value = ""
            assert await test_module.accept_taa(
                mock_ledger, self.profile, taa_info, provision=False
            )

    async def test_ledger_accept_taa(self):
        taa_info = {
            "taa_record": {"version": "1.0", "text": "Agreement"},
            "aml_record": {"aml": {"wallet_agreement": "", "on_file": ""}},
        }

        # Incorrect version
        self.profile = await create_test_profile(
            {
                "ledger.taa_acceptance_mechanism": "wallet_agreement",
                "ledger.taa_acceptance_version": "1.5",
            }
        )
        with pytest.raises(LedgerError):
            await test_module.accept_taa(None, self.profile, taa_info, provision=False)

        # Incorrect mechanism
        self.profile = await create_test_profile(
            {
                "ledger.taa_acceptance_mechanism": "not_exist",
                "ledger.taa_acceptance_version": "1.0",
            }
        )
        with pytest.raises(LedgerError):
            await test_module.accept_taa(None, self.profile, taa_info, provision=False)

        # Valid
        self.profile = await create_test_profile(
            {
                "ledger.taa_acceptance_mechanism": "on_file",
                "ledger.taa_acceptance_version": "1.0",
            }
        )
        mock_ledger = mock.MagicMock(BaseLedger, autospec=True)
        mock_ledger.get_txn_author_agreement = mock.CoroutineMock()
        assert await test_module.accept_taa(
            mock_ledger, self.profile, taa_info, provision=False
        )

    async def test_ledger_config(self):
        """Test required argument parsing."""

        parser = argparse.create_argument_parser()
        group = argparse.LedgerGroup()
        group.add_arguments(parser)

        with mock.patch.object(parser, "exit") as exit_parser:
            parser.parse_args(["-h"])
            exit_parser.assert_called_once()

        result = parser.parse_args(
            [
                "--genesis-url",
                "http://1.2.3.4:9000/genesis",
                "--ledger-keepalive",
                "10",
            ]
        )

        assert result.ledger_keepalive == 10
        assert result.genesis_url == "http://1.2.3.4:9000/genesis"

        settings = group.get_settings(result)

        assert settings["ledger.keepalive"] == result.ledger_keepalive
        assert settings["ledger.genesis_url"] == result.genesis_url
