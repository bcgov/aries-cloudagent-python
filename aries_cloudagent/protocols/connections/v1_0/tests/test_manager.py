from unittest.mock import call
from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from .....cache.base import BaseCache
from .....cache.in_memory import InMemoryCache
from .....config.base import InjectionError
from .....connections.models.conn_record import ConnRecord
from .....connections.models.connection_target import ConnectionTarget
from .....connections.base_manager import (
    BaseConnectionManager,
    BaseConnectionManagerError,
)
from .....connections.models.diddoc import DIDDoc, PublicKey, PublicKeyType, Service
from .....core.in_memory import InMemoryProfile
from .....ledger.base import BaseLedger
from .....messaging.responder import BaseResponder, MockResponder
from .....protocols.routing.v1_0.manager import RoutingManager
from .....storage.error import StorageNotFoundError
from .....transport.inbound.receipt import MessageReceipt
from .....wallet.base import DIDInfo, KeyInfo
from .....wallet.error import WalletNotFoundError
from .....wallet.in_memory import InMemoryWallet
from .....wallet.util import naked_to_did_key
from ....coordinate_mediation.v1_0.models.mediation_record import MediationRecord
from ....coordinate_mediation.v1_0.manager import MediationManager
from ....coordinate_mediation.v1_0.messages.keylist_update import KeylistUpdate
from ....coordinate_mediation.v1_0.messages.mediate_request import MediationRequest
from ....coordinate_mediation.v1_0.messages.inner.keylist_update_rule import (
    KeylistUpdateRule,
)
from .....multitenant.manager import MultitenantManager
from ..manager import ConnectionManager, ConnectionManagerError
from ..messages.connection_invitation import ConnectionInvitation
from ..messages.connection_request import ConnectionRequest
from ..messages.connection_response import ConnectionResponse
from ..models.connection_detail import ConnectionDetail


class TestConnectionManager(AsyncTestCase):
    def make_did_doc(self, did, verkey):
        doc = DIDDoc(did=did)
        controller = did
        ident = "1"
        pk_value = verkey
        pk = PublicKey(
            did, ident, pk_value, PublicKeyType.ED25519_SIG_2018, controller, False
        )
        doc.set(pk)
        recip_keys = [pk]
        router_keys = []
        service = Service(
            did, "indy", "IndyAgent", recip_keys, router_keys, self.test_endpoint
        )
        doc.set(service)
        return doc

    async def setUp(self):
        self.test_seed = "testseed000000000000000000000001"
        self.test_did = "did:peer:55GkHamhTU1ZbTbV2ab9DE"
        self.test_verkey = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
        self.test_endpoint = "http://localhost"

        self.test_target_did = "GbuDUYXaUZRfHD2jeDuQuP"
        self.test_target_verkey = "9WCgWKUaAJj3VWxxtzvvMQN3AoFxoBtBDo9ntwJnVVCC"

        self.responder = MockResponder()

        self.session = InMemoryProfile.test_session(
            {
                "default_endpoint": "http://aries.ca/endpoint",
                "default_label": "This guy",
                "additional_endpoints": ["http://aries.ca/another-endpoint"],
                "debug.auto_accept_invites": True,
                "debug.auto_accept_requests": True,
            },
            bind={BaseResponder: self.responder, BaseCache: InMemoryCache()},
        )
        self.context = self.session.context

        self.multitenant_mgr = async_mock.MagicMock(MultitenantManager, autospec=True)
        self.session.context.injector.bind_instance(
            MultitenantManager, self.multitenant_mgr
        )

        self.test_mediator_routing_keys = [
            "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRR"
        ]
        self.test_mediator_conn_id = "mediator-conn-id"
        self.test_mediator_endpoint = "http://mediator.example.com"

        self.manager = ConnectionManager(self.session)
        assert self.manager.session

    async def test_create_invitation_public_and_multi_use_fails(self):
        self.context.update_settings({"public_invites": True})
        with async_mock.patch.object(
            InMemoryWallet, "get_public_did", autospec=True
        ) as mock_wallet_get_public_did:
            mock_wallet_get_public_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )
            with self.assertRaises(ConnectionManagerError):
                await self.manager.create_invitation(public=True, multi_use=True)

    async def test_create_invitation_non_multi_use_invitation_fails_on_reuse(self):
        connect_record, connect_invite = await self.manager.create_invitation()

        receipt = MessageReceipt(recipient_verkey=connect_record.invitation_key)

        requestA = ConnectionRequest(
            connection=ConnectionDetail(
                did=self.test_target_did,
                did_doc=self.make_did_doc(
                    self.test_target_did, self.test_target_verkey
                ),
            ),
            label="SameInviteRequestA",
        )

        await self.manager.receive_request(requestA, receipt)

        requestB = ConnectionRequest(
            connection=ConnectionDetail(
                did=self.test_did,
                did_doc=self.make_did_doc(self.test_did, self.test_verkey),
            ),
            label="SameInviteRequestB",
        )

        # requestB fails because the invitation was not set to multi-use
        rr_awaitable = self.manager.receive_request(requestB, receipt)
        await self.assertAsyncRaises(ConnectionManagerError, rr_awaitable)

    async def test_create_invitation_public(self):
        self.context.update_settings({"public_invites": True})

        with async_mock.patch.object(
            InMemoryWallet, "get_public_did", autospec=True
        ) as mock_wallet_get_public_did:
            mock_wallet_get_public_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )
            connect_record, connect_invite = await self.manager.create_invitation(
                public=True, my_endpoint="testendpoint"
            )

            assert connect_record is None
            assert connect_invite.did.endswith(self.test_did)

    async def test_create_invitation_multitenant(self):
        self.context.update_settings(
            {"wallet.id": "test_wallet", "multitenant.enabled": True}
        )

        with async_mock.patch.object(
            InMemoryWallet, "create_signing_key", autospec=True
        ) as mock_wallet_create_signing_key:
            mock_wallet_create_signing_key.return_value = KeyInfo(
                self.test_verkey, None
            )
            await self.manager.create_invitation()
            self.multitenant_mgr.add_key.assert_called_once_with(
                "test_wallet", self.test_verkey
            )

    async def test_create_invitation_public_multitenant(self):
        self.context.update_settings(
            {
                "public_invites": True,
                "wallet.id": "test_wallet",
                "multitenant.enabled": True,
            }
        )

        with async_mock.patch.object(
            InMemoryWallet, "get_public_did", autospec=True
        ) as mock_wallet_get_public_did:
            mock_wallet_get_public_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )
            await self.manager.create_invitation(public=True)
            self.multitenant_mgr.add_key.assert_called_once_with(
                "test_wallet", self.test_verkey, skip_if_exists=True
            )

    async def test_create_invitation_public_no_public_invites(self):
        self.context.update_settings({"public_invites": False})

        with self.assertRaises(ConnectionManagerError):
            await self.manager.create_invitation(
                public=True, my_endpoint="testendpoint"
            )

    async def test_create_invitation_public_no_public_did(self):
        self.context.update_settings({"public_invites": True})

        with async_mock.patch.object(
            InMemoryWallet, "get_public_did", autospec=True
        ) as mock_wallet_get_public_did:
            mock_wallet_get_public_did.return_value = None
            with self.assertRaises(ConnectionManagerError):
                await self.manager.create_invitation(
                    public=True, my_endpoint="testendpoint"
                )

    async def test_create_invitation_multi_use(self):
        connect_record, connect_invite = await self.manager.create_invitation(
            my_endpoint="testendpoint", multi_use=True
        )

        receipt = MessageReceipt(recipient_verkey=connect_record.invitation_key)

        requestA = ConnectionRequest(
            connection=ConnectionDetail(
                did=self.test_target_did,
                did_doc=self.make_did_doc(
                    self.test_target_did, self.test_target_verkey
                ),
            ),
            label="SameInviteRequestA",
        )

        await self.manager.receive_request(requestA, receipt)

        requestB = ConnectionRequest(
            connection=ConnectionDetail(
                did=self.test_did,
                did_doc=self.make_did_doc(self.test_did, self.test_verkey),
            ),
            label="SameInviteRequestB",
        )

        await self.manager.receive_request(requestB, receipt)

    async def test_create_invitation_recipient_routing_endpoint(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )
        connect_record, connect_invite = await self.manager.create_invitation(
            my_endpoint=self.test_endpoint,
            recipient_keys=[self.test_verkey],
            routing_keys=[self.test_verkey],
        )

        receipt = MessageReceipt(recipient_verkey=connect_record.invitation_key)

        requestA = ConnectionRequest(
            connection=ConnectionDetail(
                did=self.test_target_did,
                did_doc=self.make_did_doc(
                    self.test_target_did, self.test_target_verkey
                ),
            ),
            label="InviteRequestA",
        )

        await self.manager.receive_request(requestA, receipt)

    async def test_create_invitation_metadata_assigned(self):
        record, invite = await self.manager.create_invitation(
            metadata={"hello": "world"}
        )
        assert await record.metadata_get_all(self.session) == {"hello": "world"}

    async def test_create_invitation_public_and_metadata_fails(self):
        self.context.update_settings({"public_invites": True})
        with async_mock.patch.object(
            InMemoryWallet, "get_public_did", autospec=True
        ) as mock_wallet_get_public_did:
            mock_wallet_get_public_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )
            with self.assertRaises(ConnectionManagerError):
                await self.manager.create_invitation(
                    public=True, metadata={"hello": "world"}
                )

    async def test_create_invitation_multi_use_metadata_transfers_to_connection(self):
        connect_record, _ = await self.manager.create_invitation(
            my_endpoint="testendpoint", multi_use=True, metadata={"test": "value"}
        )

        receipt = MessageReceipt(recipient_verkey=connect_record.invitation_key)

        request = ConnectionRequest(
            connection=ConnectionDetail(
                did=self.test_target_did,
                did_doc=self.make_did_doc(
                    self.test_target_did, self.test_target_verkey
                ),
            ),
            label="request",
        )

        new_conn_rec = await self.manager.receive_request(request, receipt)
        assert new_conn_rec != connect_record
        assert await new_conn_rec.metadata_get_all(self.session) == {"test": "value"}

    async def test_create_invitation_mediation_overwrites_routing_and_endpoint(self):
        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)
        with async_mock.patch.object(
            MediationManager,
            "get_default_mediator",
        ) as mock_get_default_mediator:
            _, invite = await self.manager.create_invitation(
                routing_keys=[self.test_verkey],
                my_endpoint=self.test_endpoint,
                mediation_id=mediation_record.mediation_id,
            )
            assert invite.routing_keys == self.test_mediator_routing_keys
            assert invite.endpoint == self.test_mediator_endpoint
            mock_get_default_mediator.assert_not_called()

    async def test_create_invitation_mediation_using_default(self):
        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)
        with async_mock.patch.object(
            MediationManager,
            "get_default_mediator",
            async_mock.CoroutineMock(return_value=mediation_record),
        ) as mock_get_default_mediator:
            _, invite = await self.manager.create_invitation(
                routing_keys=[self.test_verkey],
                my_endpoint=self.test_endpoint,
            )
            assert invite.routing_keys == self.test_mediator_routing_keys
            assert invite.endpoint == self.test_mediator_endpoint
            mock_get_default_mediator.assert_called_once()

    async def test_receive_invitation(self):
        (_, connect_invite) = await self.manager.create_invitation(
            my_endpoint="testendpoint"
        )

        invitee_record = await self.manager.receive_invitation(connect_invite)
        assert ConnRecord.State.get(invitee_record.state) is ConnRecord.State.REQUEST

    async def test_receive_invitation_no_auto_accept(self):
        (_, connect_invite) = await self.manager.create_invitation(
            my_endpoint="testendpoint"
        )

        invitee_record = await self.manager.receive_invitation(
            connect_invite, auto_accept=False
        )
        assert ConnRecord.State.get(invitee_record.state) is ConnRecord.State.INVITATION

    async def test_receive_invitation_bad_invitation(self):
        x_invites = [
            ConnectionInvitation(),
            ConnectionInvitation(
                recipient_keys=["3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"]
            ),
        ]

        for x_invite in x_invites:
            with self.assertRaises(ConnectionManagerError):
                await self.manager.receive_invitation(x_invite)

    async def test_receive_invitation_with_did(self):
        """Test invitation received with a public DID instead of service info."""
        invite = ConnectionInvitation(did=self.test_did)
        invitee_record = await self.manager.receive_invitation(invite)
        assert ConnRecord.State.get(invitee_record.state) is ConnRecord.State.REQUEST

    async def test_receive_invitation_mediation_passes_id_when_auto_accept(self):
        with async_mock.patch.object(
            ConnectionManager, "create_request"
        ) as create_request:
            record, connect_invite = await self.manager.create_invitation(
                my_endpoint="testendpoint"
            )

            invitee_record = await self.manager.receive_invitation(
                connect_invite, mediation_id="test-mediation-id", auto_accept=True
            )
            create_request.assert_called_once_with(
                invitee_record, mediation_id="test-mediation-id"
            )

    async def test_receive_invitation_bad_mediation(self):
        _, connect_invite = await self.manager.create_invitation(
            my_endpoint="testendpoint"
        )
        with self.assertRaises(StorageNotFoundError):
            await self.manager.receive_invitation(
                connect_invite, mediation_id="not-a-mediation-id"
            )

    async def test_receive_invitation_mediation_not_granted(self):
        _, connect_invite = await self.manager.create_invitation(
            my_endpoint="testendpoint"
        )

        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_DENIED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)
        with self.assertRaises(BaseConnectionManagerError):
            await self.manager.receive_invitation(
                connect_invite, mediation_id=mediation_record.mediation_id
            )

        mediation_record.state = MediationRecord.STATE_REQUEST
        await mediation_record.save(self.session)
        with self.assertRaises(BaseConnectionManagerError):
            await self.manager.receive_invitation(
                connect_invite, mediation_id=mediation_record.mediation_id
            )

    async def test_create_request(self):
        conn_req = await self.manager.create_request(
            ConnRecord(
                invitation_key=self.test_verkey,
                their_label="Hello",
                their_role=ConnRecord.Role.RESPONDER.rfc160,
                alias="Bob",
            )
        )
        assert conn_req

    async def test_create_request_my_endpoint(self):
        conn_req = await self.manager.create_request(
            ConnRecord(
                invitation_key=self.test_verkey,
                their_label="Hello",
                their_role=ConnRecord.Role.RESPONDER.rfc160,
                alias="Bob",
            ),
            my_endpoint="http://testendpoint.com/endpoint",
        )
        assert conn_req

    async def test_create_request_my_did(self):
        await self.session.wallet.create_local_did(seed=None, did=self.test_did)
        conn_req = await self.manager.create_request(
            ConnRecord(
                invitation_key=self.test_verkey,
                my_did=self.test_did,
                their_label="Hello",
                their_role=ConnRecord.Role.RESPONDER.rfc160,
                alias="Bob",
            )
        )
        assert conn_req

    async def test_create_request_multitenant(self):
        self.context.update_settings(
            {"wallet.id": "test_wallet", "multitenant.enabled": True}
        )

        with async_mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did:
            mock_wallet_create_local_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )
            await self.manager.create_request(
                ConnRecord(
                    invitation_key=self.test_verkey,
                    their_label="Hello",
                    their_role=ConnRecord.Role.RESPONDER.rfc160,
                    alias="Bob",
                )
            )
            self.multitenant_mgr.add_key.assert_called_once_with(
                "test_wallet", self.test_verkey
            )

    async def test_create_request_mediation_id(self):
        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)

        record = ConnRecord(
            invitation_key=self.test_verkey,
            their_label="Hello",
            their_role=ConnRecord.Role.RESPONDER.rfc160,
            alias="Bob",
        )

        # Ensure the path with new did creation is hit
        record.my_did = None

        with async_mock.patch.object(
            ConnectionManager, "create_did_document", autospec=True
        ) as create_did_document, async_mock.patch.object(
            self.session.wallet, "create_local_did"
        ) as create_local_did, async_mock.patch.object(
            MediationManager, "get_default_mediator"
        ) as mock_get_default_mediator:

            did_info = DIDInfo(did=self.test_did, verkey=self.test_verkey, metadata={})
            create_local_did.return_value = did_info
            await self.manager.create_request(
                record,
                mediation_id=mediation_record.mediation_id,
                my_endpoint=self.test_endpoint,
            )
            create_local_did.assert_called_once_with(method_name="peer")
            create_did_document.assert_called_once_with(
                self.manager,
                did_info,
                None,
                [self.test_endpoint],
                mediation_records=[mediation_record],
                svc_type=DIDDoc.SERVICE_TYPE_V0,
            )
            mock_get_default_mediator.assert_not_called()

        assert len(self.responder.messages) == 1
        message, used_kwargs = self.responder.messages[0]
        assert isinstance(message, KeylistUpdate)
        assert (
            "connection_id" in used_kwargs
            and used_kwargs["connection_id"] == self.test_mediator_conn_id
        )

    async def test_create_request_default_mediator(self):
        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)

        record = ConnRecord(
            invitation_key=self.test_verkey,
            their_label="Hello",
            their_role=ConnRecord.Role.RESPONDER.rfc160,
            alias="Bob",
        )

        # Ensure the path with new did creation is hit
        record.my_did = None

        with async_mock.patch.object(
            ConnectionManager, "create_did_document", autospec=True
        ) as create_did_document, async_mock.patch.object(
            self.session.wallet, "create_local_did"
        ) as create_local_did, async_mock.patch.object(
            MediationManager,
            "get_default_mediator",
            async_mock.CoroutineMock(return_value=mediation_record),
        ) as mock_get_default_mediator:

            did_info = DIDInfo(did=self.test_did, verkey=self.test_verkey, metadata={})
            create_local_did.return_value = did_info
            await self.manager.create_request(
                record,
                my_endpoint=self.test_endpoint,
            )
            create_local_did.assert_called_once_with(method_name="peer")
            create_did_document.assert_called_once_with(
                self.manager,
                did_info,
                None,
                [self.test_endpoint],
                mediation_records=[mediation_record],
                svc_type=DIDDoc.SERVICE_TYPE_V0,
            )
            mock_get_default_mediator.assert_called_once()

        assert len(self.responder.messages) == 1
        message, used_kwargs = self.responder.messages[0]
        assert isinstance(message, KeylistUpdate)
        assert (
            "connection_id" in used_kwargs
            and used_kwargs["connection_id"] == self.test_mediator_conn_id
        )

    async def test_create_request_bad_mediation(self):
        record, _ = await self.manager.create_invitation(my_endpoint="testendpoint")
        with self.assertRaises(StorageNotFoundError):
            await self.manager.create_request(record, mediation_id="not-a-mediation-id")

    async def test_create_request_mediation_not_granted(self):
        record, _ = await self.manager.create_invitation(my_endpoint="testendpoint")

        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_DENIED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)
        with self.assertRaises(BaseConnectionManagerError):
            await self.manager.create_request(
                record, mediation_id=mediation_record.mediation_id
            )

        mediation_record.state = MediationRecord.STATE_REQUEST
        await mediation_record.save(self.session)
        with self.assertRaises(BaseConnectionManagerError):
            await self.manager.create_request(
                record, mediation_id=mediation_record.mediation_id
            )

    async def test_receive_request_public_did(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = self.test_did

        receipt = MessageReceipt(recipient_did=self.test_did, recipient_did_public=True)

        await self.session.wallet.create_local_did(seed=None, did=self.test_did)

        self.context.update_settings({"public_invites": True})
        with async_mock.patch.object(
            ConnRecord, "connection_id", autospec=True
        ), async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_id", autospec=True
        ) as mock_conn_retrieve_by_id, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            conn_rec = await self.manager.receive_request(mock_request, receipt)
            assert conn_rec

        messages = self.responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert type(result) == ConnectionResponse
        assert "connection_id" in target

    async def test_receive_request_multi_use_multitenant(self):
        multiuse_info = await self.session.wallet.create_local_did()
        new_info = await self.session.wallet.create_local_did()

        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock(
            is_multiuse_invitation=True, invitation_key=multiuse_info.verkey
        )
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = self.test_did
        receipt = MessageReceipt(recipient_verkey=multiuse_info.verkey)

        self.context.update_settings(
            {"wallet.id": "test_wallet", "multitenant.enabled": True}
        )
        with async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ), async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ), async_mock.patch.object(
            ConnRecord, "retrieve_by_invitation_key"
        ) as mock_conn_retrieve_by_invitation_key, async_mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did:
            mock_wallet_create_local_did.return_value = DIDInfo(
                new_info.did, new_info.verkey, None
            )
            mock_conn_retrieve_by_invitation_key.return_value = async_mock.MagicMock(
                connection_id="dummy",
                retrieve_invitation=async_mock.CoroutineMock(return_value={}),
                metadata_get_all=async_mock.CoroutineMock(return_value={}),
            )
            await self.manager.receive_request(mock_request, receipt)

            self.multitenant_mgr.add_key.assert_called_once_with(
                "test_wallet", new_info.verkey
            )

    async def test_receive_request_public_multitenant(self):
        new_info = await self.session.wallet.create_local_did()

        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock(accept=ConnRecord.ACCEPT_MANUAL)
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = self.test_did
        receipt = MessageReceipt(recipient_did_public=True)

        self.context.update_settings(
            {
                "wallet.id": "test_wallet",
                "multitenant.enabled": True,
                "public_invites": True,
                "debug.auto_accept_requests": False,
            }
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ), async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ), async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ), async_mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did, async_mock.patch.object(
            InMemoryWallet, "get_local_did", autospec=True
        ) as mock_wallet_get_local_did:
            mock_wallet_create_local_did.return_value = DIDInfo(
                new_info.did, new_info.verkey, None
            )
            mock_wallet_get_local_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )
            await self.manager.receive_request(mock_request, receipt)

            self.multitenant_mgr.add_key.assert_called_once_with(
                "test_wallet", new_info.verkey
            )

    async def test_receive_request_public_did_no_did_doc(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = None

        receipt = MessageReceipt(recipient_did=self.test_did, recipient_did_public=True)

        await self.session.wallet.create_local_did(seed=None, did=self.test_did)

        self.context.update_settings({"public_invites": True})
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_id", autospec=True
        ) as mock_conn_retrieve_by_id, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            with self.assertRaises(ConnectionManagerError):
                await self.manager.receive_request(mock_request, receipt)

    async def test_receive_request_public_did_wrong_did(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = "dummy"

        receipt = MessageReceipt(recipient_did=self.test_did, recipient_did_public=True)

        await self.session.wallet.create_local_did(seed=None, did=self.test_did)

        self.context.update_settings({"public_invites": True})
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_id", autospec=True
        ) as mock_conn_retrieve_by_id, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            with self.assertRaises(ConnectionManagerError):
                await self.manager.receive_request(mock_request, receipt)

    async def test_receive_request_public_did_no_public_invites(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = self.test_did

        receipt = MessageReceipt(recipient_did=self.test_did, recipient_did_public=True)

        await self.session.wallet.create_local_did(seed=None, did=self.test_did)

        self.context.update_settings({"public_invites": False})
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_id", autospec=True
        ) as mock_conn_retrieve_by_id, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            with self.assertRaises(ConnectionManagerError):
                await self.manager.receive_request(mock_request, receipt)

    async def test_receive_request_public_did_no_auto_accept(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = self.test_did

        receipt = MessageReceipt(recipient_did=self.test_did, recipient_did_public=True)

        await self.session.wallet.create_local_did(seed=None, did=self.test_did)

        self.context.update_settings(
            {"public_invites": True, "debug.auto_accept_requests": False}
        )
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_id", autospec=True
        ) as mock_conn_retrieve_by_id, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            conn_rec = await self.manager.receive_request(mock_request, receipt)
            assert conn_rec

        messages = self.responder.messages
        assert not messages

    async def test_receive_request_mediation_id(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = self.test_did

        receipt = MessageReceipt(
            recipient_did=self.test_did, recipient_did_public=False
        )

        await self.session.wallet.create_local_did(seed=None, did=self.test_did)

        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)

        record, invite = await self.manager.create_invitation()
        record.accept = ConnRecord.ACCEPT_MANUAL
        await record.save(self.session)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_invitation_key"
        ) as mock_conn_retrieve_by_invitation_key, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            mock_conn_retrieve_by_invitation_key.return_value = record
            conn_rec = await self.manager.receive_request(
                mock_request, receipt, mediation_id=mediation_record.mediation_id
            )

        assert len(self.responder.messages) == 1
        message, target = self.responder.messages[0]
        assert isinstance(message, KeylistUpdate)
        assert len(message.updates) == 1
        (remove,) = message.updates
        assert remove.action == KeylistUpdateRule.RULE_REMOVE
        assert remove.recipient_key == record.invitation_key

    async def test_receive_request_bad_mediation(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = async_mock.MagicMock()
        mock_request.connection.did_doc.did = self.test_did
        receipt = MessageReceipt(
            recipient_did=self.test_did, recipient_did_public=False
        )
        record, invite = await self.manager.create_invitation()
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_invitation_key"
        ) as mock_conn_retrieve_by_invitation_key, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            mock_conn_retrieve_by_invitation_key.return_value = record
            with self.assertRaises(StorageNotFoundError):
                await self.manager.receive_request(
                    mock_request, receipt, mediation_id="not-a-mediation-id"
                )

    async def test_receive_request_mediation_not_granted(self):
        mock_request = async_mock.MagicMock()
        mock_request.connection = async_mock.MagicMock()
        mock_request.connection.did = self.test_did
        mock_request.connection.did_doc = self.make_did_doc(
            self.test_target_did, self.test_target_verkey
        )
        mock_request.connection.did_doc.did = self.test_did
        receipt = MessageReceipt(
            recipient_did=self.test_did, recipient_did_public=False
        )
        record, invite = await self.manager.create_invitation()

        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_DENIED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "attach_request", autospec=True
        ) as mock_conn_attach_request, async_mock.patch.object(
            ConnRecord, "retrieve_by_invitation_key"
        ) as mock_conn_retrieve_by_invitation_key, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ):
            mock_conn_retrieve_by_invitation_key.return_value = record
            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.receive_request(
                    mock_request, receipt, mediation_id=mediation_record.mediation_id
                )

            mediation_record.state = MediationRecord.STATE_REQUEST
            await mediation_record.save(self.session)
            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.receive_request(
                    mock_request, receipt, mediation_id=mediation_record.mediation_id
                )

    async def test_create_response(self):
        conn_rec = ConnRecord(state=ConnRecord.State.REQUEST.rfc160)

        with async_mock.patch.object(
            ConnRecord, "log_state", autospec=True
        ) as mock_conn_log_state, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ) as mock_conn_retrieve_request, async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_save, async_mock.patch.object(
            ConnectionResponse, "sign_field", autospec=True
        ) as mock_sign, async_mock.patch.object(
            conn_rec, "metadata_get", async_mock.CoroutineMock()
        ):
            await self.manager.create_response(conn_rec, "http://10.20.30.40:5060/")

    async def test_create_response_multitenant(self):
        self.context.update_settings(
            {"wallet.id": "test_wallet", "multitenant.enabled": True}
        )

        with async_mock.patch.object(
            ConnectionResponse, "sign_field", autospec=True
        ), async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ), async_mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did:
            mock_wallet_create_local_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )
            await self.manager.create_response(
                ConnRecord(
                    state=ConnRecord.State.REQUEST,
                )
            )
            self.multitenant_mgr.add_key.assert_called_once_with(
                "test_wallet", self.test_verkey
            )

    async def test_create_response_bad_state(self):
        with self.assertRaises(ConnectionManagerError):
            await self.manager.create_response(
                ConnRecord(
                    invitation_key=self.test_verkey,
                    their_label="Hello",
                    their_role=ConnRecord.Role.RESPONDER.rfc160,
                    alias="Bob",
                    state=ConnRecord.State.ABANDONED.rfc160,
                )
            )

    async def test_create_response_mediation(self):
        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        await mediation_record.save(self.session)

        conn_rec = ConnRecord(
            state=ConnRecord.State.REQUEST.rfc160,
        )
        conn_rec.my_did = None

        with async_mock.patch.object(
            ConnRecord, "log_state", autospec=True
        ) as mock_conn_log_state, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ) as mock_conn_retrieve_request, async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_save, async_mock.patch.object(
            ConnectionResponse, "sign_field", autospec=True
        ) as mock_sign, async_mock.patch.object(
            conn_rec, "metadata_get", async_mock.CoroutineMock(return_value=False)
        ):
            await self.manager.create_response(
                conn_rec, mediation_id=mediation_record.mediation_id
            )

        assert len(self.responder.messages) == 1
        message, target = self.responder.messages[0]
        assert isinstance(message, KeylistUpdate)
        assert len(message.updates) == 1
        (add,) = message.updates
        assert add.action == KeylistUpdateRule.RULE_ADD
        assert add.recipient_key

    async def test_create_response_bad_mediation(self):
        record = async_mock.MagicMock()
        with self.assertRaises(StorageNotFoundError):
            await self.manager.create_response(
                record, mediation_id="not-a-mediation-id"
            )

    async def test_create_response_mediation_not_granted(self):
        record = ConnRecord(state=ConnRecord.State.REQUEST)
        with async_mock.patch.object(
            ConnRecord, "retrieve_request"
        ) as retrieve_request, async_mock.patch.object(
            ConnectionResponse, "sign_field", autospec=True
        ) as mock_sign:
            mediation_record = MediationRecord(
                role=MediationRecord.ROLE_CLIENT,
                state=MediationRecord.STATE_DENIED,
                connection_id=self.test_mediator_conn_id,
                routing_keys=self.test_mediator_routing_keys,
                endpoint=self.test_mediator_endpoint,
            )
            await mediation_record.save(self.session)
            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.create_response(
                    record, mediation_id=mediation_record.mediation_id
                )

            mediation_record.state = MediationRecord.STATE_REQUEST
            await mediation_record.save(self.session)
            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.create_response(
                    record, mediation_id=mediation_record.mediation_id
                )

    async def test_create_response_auto_send_mediation_request(self):
        conn_rec = ConnRecord(
            state=ConnRecord.State.REQUEST.rfc160,
        )
        conn_rec.my_did = None

        with async_mock.patch.object(
            ConnRecord, "log_state", autospec=True
        ) as mock_conn_log_state, async_mock.patch.object(
            ConnRecord, "retrieve_request", autospec=True
        ) as mock_conn_retrieve_request, async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_save, async_mock.patch.object(
            ConnectionResponse, "sign_field", autospec=True
        ) as mock_sign, async_mock.patch.object(
            conn_rec, "metadata_get", async_mock.CoroutineMock(return_value=True)
        ):
            await self.manager.create_response(conn_rec)

        assert len(self.responder.messages) == 1
        message, target = self.responder.messages[0]
        assert isinstance(message, MediationRequest)
        assert target["connection_id"] == conn_rec.connection_id

    async def test_accept_response_find_by_thread_id(self):
        mock_response = async_mock.MagicMock()
        mock_response._thread = async_mock.MagicMock()
        mock_response.connection = async_mock.MagicMock()
        mock_response.connection.did = self.test_target_did
        mock_response.connection.did_doc = async_mock.MagicMock()
        mock_response.connection.did_doc.did = self.test_target_did

        receipt = MessageReceipt(recipient_did=self.test_did, recipient_did_public=True)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "retrieve_by_request_id", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, async_mock.patch.object(
            MediationManager, "get_default_mediator", async_mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.return_value = async_mock.MagicMock(
                did=self.test_target_did,
                did_doc=async_mock.MagicMock(did=self.test_target_did),
                state=ConnRecord.State.RESPONSE.rfc23,
                save=async_mock.CoroutineMock(),
                metadata_get=async_mock.CoroutineMock(),
                connection_id="test-conn-id",
            )
            conn_rec = await self.manager.accept_response(mock_response, receipt)
            assert conn_rec.their_did == self.test_target_did
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.RESPONSE

    async def test_accept_response_not_found_by_thread_id_receipt_has_sender_did(self):
        mock_response = async_mock.MagicMock()
        mock_response._thread = async_mock.MagicMock()
        mock_response.connection = async_mock.MagicMock()
        mock_response.connection.did = self.test_target_did
        mock_response.connection.did_doc = async_mock.MagicMock()
        mock_response.connection.did_doc.did = self.test_target_did

        receipt = MessageReceipt(sender_did=self.test_target_did)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "retrieve_by_request_id", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, async_mock.patch.object(
            ConnRecord, "retrieve_by_did", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_did, async_mock.patch.object(
            MediationManager, "get_default_mediator", async_mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.side_effect = StorageNotFoundError()
            mock_conn_retrieve_by_did.return_value = async_mock.MagicMock(
                did=self.test_target_did,
                did_doc=async_mock.MagicMock(did=self.test_target_did),
                state=ConnRecord.State.RESPONSE.rfc23,
                save=async_mock.CoroutineMock(),
                metadata_get=async_mock.CoroutineMock(return_value=False),
                connection_id="test-conn-id",
            )

            conn_rec = await self.manager.accept_response(mock_response, receipt)
            assert conn_rec.their_did == self.test_target_did
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.RESPONSE

            assert not self.responder.messages

    async def test_accept_response_not_found_by_thread_id_nor_receipt_sender_did(self):
        mock_response = async_mock.MagicMock()
        mock_response._thread = async_mock.MagicMock()
        mock_response.connection = async_mock.MagicMock()
        mock_response.connection.did = self.test_target_did
        mock_response.connection.did_doc = async_mock.MagicMock()
        mock_response.connection.did_doc.did = self.test_target_did

        receipt = MessageReceipt(sender_did=self.test_target_did)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "retrieve_by_request_id", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, async_mock.patch.object(
            ConnRecord, "retrieve_by_did", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_did:
            mock_conn_retrieve_by_req_id.side_effect = StorageNotFoundError()
            mock_conn_retrieve_by_did.side_effect = StorageNotFoundError()

            with self.assertRaises(ConnectionManagerError):
                await self.manager.accept_response(mock_response, receipt)

    async def test_accept_response_find_by_thread_id_bad_state(self):
        mock_response = async_mock.MagicMock()
        mock_response._thread = async_mock.MagicMock()
        mock_response.connection = async_mock.MagicMock()
        mock_response.connection.did = self.test_target_did
        mock_response.connection.did_doc = async_mock.MagicMock()
        mock_response.connection.did_doc.did = self.test_target_did

        receipt = MessageReceipt(sender_did=self.test_target_did)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "retrieve_by_request_id", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id:
            mock_conn_retrieve_by_req_id.return_value = async_mock.MagicMock(
                state=ConnRecord.State.ABANDONED.rfc23
            )

            with self.assertRaises(ConnectionManagerError):
                await self.manager.accept_response(mock_response, receipt)

    async def test_accept_response_find_by_thread_id_no_connection_did_doc(self):
        mock_response = async_mock.MagicMock()
        mock_response._thread = async_mock.MagicMock()
        mock_response.connection = async_mock.MagicMock()
        mock_response.connection.did = self.test_target_did
        mock_response.connection.did_doc = None

        receipt = MessageReceipt(sender_did=self.test_target_did)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "retrieve_by_request_id", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id:
            mock_conn_retrieve_by_req_id.return_value = async_mock.MagicMock(
                did=self.test_target_did,
                did_doc=async_mock.MagicMock(did=self.test_target_did),
                state=ConnRecord.State.RESPONSE.rfc23,
            )

            with self.assertRaises(ConnectionManagerError):
                await self.manager.accept_response(mock_response, receipt)

    async def test_accept_response_find_by_thread_id_did_mismatch(self):
        mock_response = async_mock.MagicMock()
        mock_response._thread = async_mock.MagicMock()
        mock_response.connection = async_mock.MagicMock()
        mock_response.connection.did = self.test_target_did
        mock_response.connection.did_doc = async_mock.MagicMock()
        mock_response.connection.did_doc.did = self.test_did

        receipt = MessageReceipt(sender_did=self.test_target_did)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "retrieve_by_request_id", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id:
            mock_conn_retrieve_by_req_id.return_value = async_mock.MagicMock(
                did=self.test_target_did,
                did_doc=async_mock.MagicMock(did=self.test_target_did),
                state=ConnRecord.State.RESPONSE.rfc23,
            )

            with self.assertRaises(ConnectionManagerError):
                await self.manager.accept_response(mock_response, receipt)

    async def test_accept_response_auto_send_mediation_request(self):
        mock_response = async_mock.MagicMock()
        mock_response._thread = async_mock.MagicMock()
        mock_response.connection = async_mock.MagicMock()
        mock_response.connection.did = self.test_target_did
        mock_response.connection.did_doc = async_mock.MagicMock()
        mock_response.connection.did_doc.did = self.test_target_did

        receipt = MessageReceipt(recipient_did=self.test_did, recipient_did_public=True)

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save, async_mock.patch.object(
            ConnRecord, "retrieve_by_request_id", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_req_id, async_mock.patch.object(
            MediationManager, "get_default_mediator", async_mock.CoroutineMock()
        ):
            mock_conn_retrieve_by_req_id.return_value = async_mock.MagicMock(
                did=self.test_target_did,
                did_doc=async_mock.MagicMock(did=self.test_target_did),
                state=ConnRecord.State.RESPONSE.rfc23,
                save=async_mock.CoroutineMock(),
                metadata_get=async_mock.CoroutineMock(return_value=True),
                connection_id="test-conn-id",
            )
            conn_rec = await self.manager.accept_response(mock_response, receipt)
            assert conn_rec.their_did == self.test_target_did
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.RESPONSE

            assert len(self.responder.messages) == 1
            message, target = self.responder.messages[0]
            assert isinstance(message, MediationRequest)
            assert target["connection_id"] == conn_rec.connection_id

    async def test_get_endpoints(self):
        conn_id = "dummy"

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_retrieve, async_mock.patch.object(
            InMemoryWallet, "get_local_did", autospec=True
        ) as mock_wallet_get_local_did, async_mock.patch.object(
            self.manager, "get_connection_targets", async_mock.CoroutineMock()
        ) as mock_get_conn_targets:
            mock_retrieve.return_value = async_mock.MagicMock()
            mock_wallet_get_local_did.return_value = async_mock.MagicMock(
                metadata={"endpoint": "localhost:8020"}
            )
            mock_get_conn_targets.return_value = [
                async_mock.MagicMock(endpoint="10.20.30.40:5060")
            ]
            assert await self.manager.get_endpoints(conn_id) == (
                "localhost:8020",
                "10.20.30.40:5060",
            )

    async def test_create_static_connection(self):
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save:

            _my, _their, conn_rec = await self.manager.create_static_connection(
                my_did=self.test_did,
                their_did=self.test_target_did,
                their_verkey=self.test_target_verkey,
                their_endpoint=self.test_endpoint,
            )

            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED

    async def test_create_static_connection_multitenant(self):
        self.context.update_settings(
            {"wallet.id": "test_wallet", "multitenant.enabled": True}
        )

        self.multitenant_mgr.get_default_mediator.return_value = None

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ), async_mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did:
            mock_wallet_create_local_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )

            await self.manager.create_static_connection(
                my_did=self.test_did,
                their_did=self.test_target_did,
                their_verkey=self.test_target_verkey,
                their_endpoint=self.test_endpoint,
            )

            self.multitenant_mgr.add_key.assert_called_once_with(
                "test_wallet", self.test_verkey
            )

    async def test_create_static_connection_multitenant_mediator(self):
        self.context.update_settings(
            {"wallet.id": "test_wallet", "multitenant.enabled": True}
        )

        default_mediator = async_mock.MagicMock()

        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ), async_mock.patch.object(
            InMemoryWallet, "create_local_did", autospec=True
        ) as mock_wallet_create_local_did, async_mock.patch.object(
            ConnectionManager, "create_did_document"
        ) as create_did_document, async_mock.patch.object(
            ConnectionManager, "store_did_document"
        ) as store_did_document:
            mock_wallet_create_local_did.return_value = DIDInfo(
                self.test_did, self.test_verkey, None
            )

            # With default mediator
            self.multitenant_mgr.get_default_mediator.return_value = default_mediator
            await self.manager.create_static_connection(
                my_did=self.test_did,
                their_did=self.test_target_did,
                their_verkey=self.test_target_verkey,
                their_endpoint=self.test_endpoint,
            )

            # Without default mediator
            self.multitenant_mgr.get_default_mediator.return_value = None
            await self.manager.create_static_connection(
                my_did=self.test_did,
                their_did=self.test_target_did,
                their_verkey=self.test_target_verkey,
                their_endpoint=self.test_endpoint,
            )

            assert self.multitenant_mgr.add_key.call_count is 2

            their_info = DIDInfo(self.test_target_did, self.test_target_verkey, {})
            create_did_document.assert_has_calls(
                [
                    call(
                        their_info,
                        None,
                        [self.test_endpoint],
                        mediation_records=[default_mediator],
                        svc_type=DIDDoc.SERVICE_TYPE_V0,
                    ),
                    call(
                        their_info,
                        None,
                        [self.test_endpoint],
                        mediation_records=None,
                        svc_type=DIDDoc.SERVICE_TYPE_V0,
                    ),
                ]
            )

    async def test_create_static_connection_no_their(self):
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save:

            with self.assertRaises(ConnectionManagerError):
                await self.manager.create_static_connection(
                    my_did=self.test_did,
                    their_did=None,
                    their_verkey=self.test_target_verkey,
                    their_endpoint=self.test_endpoint,
                )

    async def test_create_static_connection_their_seed_only(self):
        with async_mock.patch.object(
            ConnRecord, "save", autospec=True
        ) as mock_conn_rec_save:

            _my, _their, conn_rec = await self.manager.create_static_connection(
                my_did=self.test_did,
                their_seed=self.test_seed,
                their_endpoint=self.test_endpoint,
            )

            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED

    async def test_find_connection_retrieve_by_did(self):
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_did", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_did:
            mock_conn_retrieve_by_did.return_value = async_mock.MagicMock(
                state=ConnRecord.State.RESPONSE.rfc23,
                save=async_mock.CoroutineMock(),
            )

            conn_rec = await self.manager.find_connection(
                their_did=self.test_target_did,
                my_did=self.test_did,
                my_verkey=self.test_verkey,
                auto_complete=True,
            )
            assert ConnRecord.State.get(conn_rec.state) is ConnRecord.State.COMPLETED

    async def test_find_connection_retrieve_by_invitation_key(self):
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_did", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_did, async_mock.patch.object(
            ConnRecord, "retrieve_by_invitation_key", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_invitation_key:
            mock_conn_retrieve_by_did.side_effect = StorageNotFoundError()
            mock_conn_retrieve_by_invitation_key.return_value = async_mock.MagicMock(
                state=ConnRecord.State.RESPONSE,
                save=async_mock.CoroutineMock(),
            )

            conn_rec = await self.manager.find_connection(
                their_did=self.test_target_did,
                my_did=self.test_did,
                my_verkey=self.test_verkey,
            )
            assert conn_rec

    async def test_find_connection_retrieve_none_by_invitation_key(self):
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_did", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_did, async_mock.patch.object(
            ConnRecord, "retrieve_by_invitation_key", async_mock.CoroutineMock()
        ) as mock_conn_retrieve_by_invitation_key:
            mock_conn_retrieve_by_did.side_effect = StorageNotFoundError()
            mock_conn_retrieve_by_invitation_key.side_effect = StorageNotFoundError()

            conn_rec = await self.manager.find_connection(
                their_did=self.test_target_did,
                my_did=self.test_did,
                my_verkey=self.test_verkey,
            )
            assert conn_rec is None

    async def test_find_inbound_connection(self):
        receipt = MessageReceipt(
            sender_verkey=self.test_verkey,
            recipient_verkey=self.test_target_verkey,
            recipient_did_public=False,
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.connection_id = "dummy"

        # First pass: not yet in cache
        with async_mock.patch.object(
            ConnectionManager, "resolve_inbound_connection", async_mock.CoroutineMock()
        ) as mock_conn_mgr_resolve_conn:
            mock_conn_mgr_resolve_conn.return_value = mock_conn

            conn_rec = await self.manager.find_inbound_connection(receipt)
            assert conn_rec

        # Second pass: in cache
        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            conn_rec = await self.manager.find_inbound_connection(receipt)
            assert conn_rec.id == mock_conn.id

    async def test_find_inbound_connection_no_cache(self):
        receipt = MessageReceipt(
            sender_verkey=self.test_verkey,
            recipient_verkey=self.test_target_verkey,
            recipient_did_public=False,
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.connection_id = "dummy"

        with async_mock.patch.object(
            ConnectionManager, "resolve_inbound_connection", async_mock.CoroutineMock()
        ) as mock_conn_mgr_resolve_conn:
            self.context.injector.clear_binding(BaseCache)
            mock_conn_mgr_resolve_conn.return_value = mock_conn

            conn_rec = await self.manager.find_inbound_connection(receipt)
            assert conn_rec

    async def test_resolve_inbound_connection(self):
        receipt = MessageReceipt(
            sender_verkey=self.test_verkey,
            recipient_verkey=self.test_target_verkey,
            recipient_did_public=True,
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.connection_id = "dummy"

        with async_mock.patch.object(
            InMemoryWallet, "get_local_did_for_verkey", async_mock.CoroutineMock()
        ) as mock_wallet_get_local_did_for_verkey, async_mock.patch.object(
            self.manager, "find_connection", async_mock.CoroutineMock()
        ) as mock_mgr_find_conn:
            mock_wallet_get_local_did_for_verkey.return_value = DIDInfo(
                self.test_did, self.test_verkey, {"public": True}
            )
            mock_mgr_find_conn.return_value = mock_conn

            assert await self.manager.resolve_inbound_connection(receipt)

    async def test_resolve_inbound_connection_injector_error(self):
        receipt = MessageReceipt(
            sender_verkey=self.test_verkey,
            recipient_verkey=self.test_target_verkey,
            recipient_did_public=True,
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.connection_id = "dummy"

        with async_mock.patch.object(
            InMemoryWallet, "get_local_did_for_verkey", async_mock.CoroutineMock()
        ) as mock_wallet_get_local_did_for_verkey, async_mock.patch.object(
            self.manager, "find_connection", async_mock.CoroutineMock()
        ) as mock_mgr_find_conn:
            mock_wallet_get_local_did_for_verkey.side_effect = InjectionError()
            mock_mgr_find_conn.return_value = mock_conn

            assert await self.manager.resolve_inbound_connection(receipt)

    async def test_resolve_inbound_connection_wallet_not_found_error(self):
        receipt = MessageReceipt(
            sender_verkey=self.test_verkey,
            recipient_verkey=self.test_target_verkey,
            recipient_did_public=True,
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.connection_id = "dummy"

        with async_mock.patch.object(
            InMemoryWallet, "get_local_did_for_verkey", async_mock.CoroutineMock()
        ) as mock_wallet_get_local_did_for_verkey, async_mock.patch.object(
            self.manager, "find_connection", async_mock.CoroutineMock()
        ) as mock_mgr_find_conn:
            mock_wallet_get_local_did_for_verkey.side_effect = WalletNotFoundError()
            mock_mgr_find_conn.return_value = mock_conn

            assert await self.manager.resolve_inbound_connection(receipt)

    async def test_create_did_document(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )

        mock_conn = async_mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=self.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )

        did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        for i in range(2):  # first cover store-record, then update-value
            await self.manager.store_did_document(did_doc)

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            did_doc = await self.manager.create_did_document(
                did_info=did_info,
                inbound_connection_id="dummy",
                svc_endpoints=[self.test_endpoint],
            )

    async def test_create_did_document_not_active(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )

        mock_conn = async_mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=self.test_target_did,
            state=ConnRecord.State.ABANDONED.rfc23,
        )

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.create_did_document(
                    did_info=did_info,
                    inbound_connection_id="dummy",
                    svc_endpoints=[self.test_endpoint],
                )

    async def test_create_did_document_no_services(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )

        mock_conn = async_mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=self.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )

        x_did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        x_did_doc._service = {}
        for i in range(2):  # first cover store-record, then update-value
            await self.manager.store_did_document(x_did_doc)

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.create_did_document(
                    did_info=did_info,
                    inbound_connection_id="dummy",
                    svc_endpoints=[self.test_endpoint],
                )

    async def test_create_did_document_no_service_endpoint(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )

        mock_conn = async_mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=self.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )

        x_did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        x_did_doc._service = {}
        x_did_doc.set(
            Service(self.test_target_did, "dummy", "IndyAgent", [], [], "", 0)
        )
        for i in range(2):  # first cover store-record, then update-value
            await self.manager.store_did_document(x_did_doc)

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.create_did_document(
                    did_info=did_info,
                    inbound_connection_id="dummy",
                    svc_endpoints=[self.test_endpoint],
                )

    async def test_create_did_document_no_service_recip_keys(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )

        mock_conn = async_mock.MagicMock(
            connection_id="dummy",
            inbound_connection_id=None,
            their_did=self.test_target_did,
            state=ConnRecord.State.COMPLETED.rfc23,
        )

        x_did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        x_did_doc._service = {}
        x_did_doc.set(
            Service(
                self.test_target_did,
                "dummy",
                "IndyAgent",
                [],
                [],
                self.test_endpoint,
                0,
            )
        )
        for i in range(2):  # first cover store-record, then update-value
            await self.manager.store_did_document(x_did_doc)

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            with self.assertRaises(BaseConnectionManagerError):
                await self.manager.create_did_document(
                    did_info=did_info,
                    inbound_connection_id="dummy",
                    svc_endpoints=[self.test_endpoint],
                )

    async def test_create_did_document_mediation(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )
        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        doc = await self.manager.create_did_document(
            did_info, mediation_records=[mediation_record]
        )
        assert doc.service
        services = list(doc.service.values())
        assert len(services) == 1
        (service,) = services
        service_public_keys = service.routing_keys[0]
        assert service_public_keys.value == mediation_record.routing_keys[0]
        assert service.endpoint == mediation_record.endpoint

    async def test_create_did_document_multiple_mediators(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )
        mediation_record1 = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        mediation_record2 = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id="mediator-conn-id2",
            routing_keys=["05e8afd1-b4f0-46b7-a285-7a08c8a37caf"],
            endpoint="http://mediatorw.example.com",
        )
        doc = await self.manager.create_did_document(
            did_info, mediation_records=[mediation_record1, mediation_record2]
        )
        assert doc.service
        services = list(doc.service.values())
        assert len(services) == 1
        (service,) = services
        assert service.routing_keys[0].value == mediation_record1.routing_keys[0]
        assert service.routing_keys[1].value == mediation_record2.routing_keys[0]
        assert service.endpoint == mediation_record2.endpoint

    async def test_create_did_document_mediation_svc_endpoints_overwritten(self):
        did_info = DIDInfo(
            self.test_did,
            self.test_verkey,
            None,
        )
        mediation_record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            state=MediationRecord.STATE_GRANTED,
            connection_id=self.test_mediator_conn_id,
            routing_keys=self.test_mediator_routing_keys,
            endpoint=self.test_mediator_endpoint,
        )
        doc = await self.manager.create_did_document(
            did_info,
            svc_endpoints=[self.test_endpoint],
            mediation_records=[mediation_record],
        )
        assert doc.service
        services = list(doc.service.values())
        assert len(services) == 1
        (service,) = services
        service_public_keys = service.routing_keys[0]
        assert service_public_keys.value == mediation_record.routing_keys[0]
        assert service.endpoint == mediation_record.endpoint

    async def test_did_key_storage(self):
        await self.manager.add_key_for_did(
            did=self.test_target_did, key=self.test_target_verkey
        )

        did = await self.manager.find_did_for_key(key=self.test_target_verkey)
        assert did == self.test_target_did
        await self.manager.remove_keys_for_did(self.test_target_did)

    async def test_get_connection_targets_conn_invitation_no_did(self):
        local_did = await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        await self.manager.store_did_document(did_doc)

        # First pass: not yet in cache
        conn_invite = ConnectionInvitation(
            did=None,
            endpoint=self.test_endpoint,
            recipient_keys=[self.test_target_verkey],
            routing_keys=[self.test_verkey],
            label="label",
        )
        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_target_did,
            connection_id="dummy",
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            retrieve_invitation=async_mock.CoroutineMock(return_value=conn_invite),
        )

        targets = await self.manager.get_connection_targets(
            connection_id=None,
            connection=mock_conn,
        )
        assert len(targets) == 1
        target = targets[0]
        assert target.did == mock_conn.their_did
        assert target.endpoint == conn_invite.endpoint
        assert target.label == conn_invite.label
        assert target.recipient_keys == conn_invite.recipient_keys
        assert target.routing_keys == conn_invite.routing_keys
        assert target.sender_key == local_did.verkey

        # Next pass: exercise cache
        targets = await self.manager.get_connection_targets(
            connection_id=None,
            connection=mock_conn,
        )
        assert len(targets) == 1
        target = targets[0]
        assert target.did == mock_conn.their_did
        assert target.endpoint == conn_invite.endpoint
        assert target.label == conn_invite.label
        assert target.recipient_keys == conn_invite.recipient_keys
        assert target.routing_keys == conn_invite.routing_keys
        assert target.sender_key == local_did.verkey

    async def test_get_connection_targets_retrieve_connection(self):
        local_did = await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        await self.manager.store_did_document(did_doc)

        # Connection target not in cache
        conn_invite = ConnectionInvitation(
            did=None,
            endpoint=self.test_endpoint,
            recipient_keys=[self.test_target_verkey],
            routing_keys=[self.test_verkey],
            label="label",
        )
        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_target_did,
            connection_id="dummy",
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            retrieve_invitation=async_mock.CoroutineMock(return_value=conn_invite),
        )

        with async_mock.patch.object(
            ConnectionTarget, "serialize", autospec=True
        ) as mock_conn_target_ser, async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn
            mock_conn_target_ser.return_value = {"serialized": "value"}
            targets = await self.manager.get_connection_targets(
                connection_id="dummy",
                connection=None,
            )
            assert len(targets) == 1
            target = targets[0]
            assert target.did == mock_conn.their_did
            assert target.endpoint == conn_invite.endpoint
            assert target.label == conn_invite.label
            assert target.recipient_keys == conn_invite.recipient_keys
            assert target.routing_keys == conn_invite.routing_keys
            assert target.sender_key == local_did.verkey

    async def test_get_conn_targets_conn_invitation_no_cache(self):
        self.context.injector.clear_binding(BaseCache)
        local_did = await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        await self.manager.store_did_document(did_doc)

        conn_invite = ConnectionInvitation(
            did=None,
            endpoint=self.test_endpoint,
            recipient_keys=[self.test_target_verkey],
            routing_keys=[self.test_verkey],
            label="label",
        )
        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_target_did,
            connection_id="dummy",
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            retrieve_invitation=async_mock.CoroutineMock(return_value=conn_invite),
        )

        targets = await self.manager.get_connection_targets(
            connection_id=None,
            connection=mock_conn,
        )
        assert len(targets) == 1
        target = targets[0]
        assert target.did == mock_conn.their_did
        assert target.endpoint == conn_invite.endpoint
        assert target.label == conn_invite.label
        assert target.recipient_keys == conn_invite.recipient_keys
        assert target.routing_keys == conn_invite.routing_keys
        assert target.sender_key == local_did.verkey

    async def test_fetch_connection_targets_no_my_did(self):
        mock_conn = async_mock.MagicMock()
        mock_conn.my_did = None
        assert await self.manager.fetch_connection_targets(mock_conn) is None

    async def test_fetch_connection_targets_conn_invitation_did_no_ledger(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        conn_invite = ConnectionInvitation(
            did=self.test_target_did,
            endpoint=self.test_endpoint,
            recipient_keys=[self.test_target_verkey],
            routing_keys=[self.test_verkey],
            label="label",
        )
        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_target_did,
            connection_id="dummy",
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            retrieve_invitation=async_mock.CoroutineMock(return_value=conn_invite),
        )

        with self.assertRaises(BaseConnectionManagerError):
            await self.manager.fetch_connection_targets(mock_conn)

    async def test_fetch_connection_targets_conn_invitation_did_ledger(self):
        self.ledger = async_mock.MagicMock()
        self.ledger.get_endpoint_for_did = async_mock.CoroutineMock(
            return_value=self.test_endpoint
        )
        self.ledger.get_key_for_did = async_mock.CoroutineMock(
            return_value=self.test_target_verkey
        )
        self.context.injector.bind_instance(BaseLedger, self.ledger)

        local_did = await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        conn_invite = ConnectionInvitation(
            did=self.test_target_did,
            endpoint=self.test_endpoint,
            recipient_keys=[self.test_target_verkey],
            routing_keys=[self.test_verkey],
            label="label",
        )
        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_target_did,
            connection_id="dummy",
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            retrieve_invitation=async_mock.CoroutineMock(return_value=conn_invite),
        )

        targets = await self.manager.fetch_connection_targets(mock_conn)
        assert len(targets) == 1
        target = targets[0]
        assert target.did == mock_conn.their_did
        assert target.endpoint == conn_invite.endpoint
        assert target.label == conn_invite.label
        assert target.recipient_keys == conn_invite.recipient_keys
        assert target.routing_keys == []
        assert target.sender_key == local_did.verkey

    async def test_fetch_connection_targets_oob_invitation_svc_did_no_ledger(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_oob_invite = async_mock.MagicMock(service_dids=["dummy"])

        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            retrieve_invitation=async_mock.CoroutineMock(return_value=mock_oob_invite),
            state=ConnRecord.State.INVITATION.rfc23,
            their_role=ConnRecord.Role.RESPONDER.rfc23,
        )

        with self.assertRaises(BaseConnectionManagerError):
            await self.manager.fetch_connection_targets(mock_conn)

    async def test_fetch_connection_targets_oob_invitation_svc_did_ledger(self):
        self.ledger = async_mock.MagicMock()
        self.ledger.get_endpoint_for_did = async_mock.CoroutineMock(
            return_value=self.test_endpoint
        )
        self.ledger.get_key_for_did = async_mock.CoroutineMock(
            return_value=self.test_target_verkey
        )
        self.context.injector.bind_instance(BaseLedger, self.ledger)

        local_did = await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_oob_invite = async_mock.MagicMock(
            label="a label",
            their_did=self.test_target_did,
            service_dids=["dummy"],
        )
        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_target_did,
            connection_id="dummy",
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            retrieve_invitation=async_mock.CoroutineMock(return_value=mock_oob_invite),
        )

        targets = await self.manager.fetch_connection_targets(mock_conn)
        assert len(targets) == 1
        target = targets[0]
        assert target.did == mock_conn.their_did
        assert target.endpoint == self.test_endpoint
        assert target.label == mock_oob_invite.label
        assert target.recipient_keys == [self.test_target_verkey]
        assert target.routing_keys == []
        assert target.sender_key == local_did.verkey

    async def test_fetch_connection_targets_oob_invitation_svc_block_ledger(self):
        self.ledger = async_mock.MagicMock()
        self.ledger.get_endpoint_for_did = async_mock.CoroutineMock(
            return_value=self.test_endpoint
        )
        self.ledger.get_key_for_did = async_mock.CoroutineMock(
            return_value=self.test_target_verkey
        )
        self.context.injector.bind_instance(BaseLedger, self.ledger)

        local_did = await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_oob_invite = async_mock.MagicMock(
            label="a label",
            their_did=self.test_target_did,
            service_dids=None,
            service_blocks=[
                async_mock.MagicMock(
                    service_endpoint=self.test_endpoint,
                    recipient_keys=[naked_to_did_key(self.test_target_verkey)],
                    routing_keys=[],
                )
            ],
        )
        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_target_did,
            connection_id="dummy",
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            retrieve_invitation=async_mock.CoroutineMock(return_value=mock_oob_invite),
        )

        targets = await self.manager.fetch_connection_targets(mock_conn)
        assert len(targets) == 1
        target = targets[0]
        assert target.did == mock_conn.their_did
        assert target.endpoint == self.test_endpoint
        assert target.label == mock_oob_invite.label
        assert target.recipient_keys == [self.test_target_verkey]
        assert target.routing_keys == []
        assert target.sender_key == local_did.verkey

    async def test_fetch_connection_targets_conn_initiator_completed_no_their_did(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=None,
            state=ConnRecord.State.COMPLETED.rfc23,
        )
        assert await self.manager.fetch_connection_targets(mock_conn) is None

    async def test_fetch_connection_targets_conn_completed_their_did(self):
        local_did = await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        did_doc = self.make_did_doc(did=self.test_did, verkey=self.test_verkey)
        await self.manager.store_did_document(did_doc)

        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            their_did=self.test_did,
            their_label="label",
            their_role=ConnRecord.Role.REQUESTER.rfc160,
            state=ConnRecord.State.COMPLETED.rfc23,
        )

        targets = await self.manager.fetch_connection_targets(mock_conn)
        assert len(targets) == 1
        target = targets[0]
        assert target.did == mock_conn.their_did
        assert target.endpoint == self.test_endpoint
        assert target.label == mock_conn.their_label
        assert target.recipient_keys == [self.test_verkey]
        assert target.routing_keys == []
        assert target.sender_key == local_did.verkey

    async def test_diddoc_connection_targets_diddoc_underspecified(self):
        with self.assertRaises(BaseConnectionManagerError):
            self.manager.diddoc_connection_targets(None, self.test_verkey)

        x_did_doc = DIDDoc(did=None)
        with self.assertRaises(BaseConnectionManagerError):
            self.manager.diddoc_connection_targets(x_did_doc, self.test_verkey)

        x_did_doc = self.make_did_doc(
            did=self.test_target_did, verkey=self.test_target_verkey
        )
        x_did_doc._service = {}
        with self.assertRaises(BaseConnectionManagerError):
            self.manager.diddoc_connection_targets(x_did_doc, self.test_verkey)

    async def test_establish_inbound(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_conn = async_mock.MagicMock(
            my_did=self.test_did,
            is_ready=True,
            save=async_mock.CoroutineMock(),
        )

        inbound_conn_id = "dummy"

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id, async_mock.patch.object(
            RoutingManager, "send_create_route", async_mock.CoroutineMock()
        ) as mock_routing_mgr_send_create_route:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            routing_state = await self.manager.establish_inbound(
                mock_conn, inbound_conn_id, None
            )
            assert routing_state == ConnRecord.ROUTING_STATE_REQUEST

    async def test_establish_inbound_conn_rec_no_my_did(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.my_did = None
        mock_conn.is_ready = True
        mock_conn.save = async_mock.CoroutineMock()

        inbound_conn_id = "dummy"

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id, async_mock.patch.object(
            RoutingManager, "send_create_route", async_mock.CoroutineMock()
        ) as mock_routing_mgr_send_create_route:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            routing_state = await self.manager.establish_inbound(
                mock_conn, inbound_conn_id, None
            )
            assert routing_state == ConnRecord.ROUTING_STATE_REQUEST

    async def test_establish_inbound_no_conn_record(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.my_did = self.test_did
        mock_conn.is_ready = True
        mock_conn.save = async_mock.CoroutineMock()

        inbound_conn_id = "dummy"

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id, async_mock.patch.object(
            RoutingManager, "send_create_route", async_mock.CoroutineMock()
        ) as mock_routing_mgr_send_create_route:
            mock_conn_rec_retrieve_by_id.side_effect = StorageNotFoundError()

            with self.assertRaises(ConnectionManagerError):
                await self.manager.establish_inbound(mock_conn, inbound_conn_id, None)

    async def test_establish_inbound_router_not_ready(self):
        await self.session.wallet.create_local_did(
            seed=self.test_seed, did=self.test_did, metadata=None
        )

        mock_conn = async_mock.MagicMock()
        mock_conn.my_did = self.test_did
        mock_conn.is_ready = False
        mock_conn.save = async_mock.CoroutineMock()

        inbound_conn_id = "dummy"

        with async_mock.patch.object(
            ConnRecord, "retrieve_by_id", async_mock.CoroutineMock()
        ) as mock_conn_rec_retrieve_by_id, async_mock.patch.object(
            RoutingManager, "send_create_route", async_mock.CoroutineMock()
        ) as mock_routing_mgr_send_create_route:
            mock_conn_rec_retrieve_by_id.return_value = mock_conn

            with self.assertRaises(ConnectionManagerError):
                await self.manager.establish_inbound(mock_conn, inbound_conn_id, None)

    async def test_update_inbound(self):
        with async_mock.patch.object(
            ConnRecord, "query", async_mock.CoroutineMock()
        ) as mock_conn_rec_query, async_mock.patch.object(
            InMemoryWallet, "get_local_did", autospec=True
        ) as mock_wallet_get_local_did:
            mock_conn_rec_query.return_value = [
                async_mock.MagicMock(
                    my_did=None,
                    their_did=self.test_target_did,
                    their_role=None,
                    save=None,
                ),
                async_mock.MagicMock(
                    my_did=self.test_did,
                    their_did=self.test_target_did,
                    their_role=None,
                    save=async_mock.CoroutineMock(),
                ),
            ]
            mock_wallet_get_local_did.return_value = async_mock.CoroutineMock(
                verkey=self.test_verkey
            )
            await self.manager.update_inbound(
                "dummy", self.test_verkey, ConnRecord.ROUTING_STATE_ACTIVE
            )
            mock_conn_rec_query.return_value[1].save.assert_called_once_with(
                self.session
            )
