"""Manager for Mediation coordination."""
import json
import logging
from typing import Optional, Sequence, Tuple

from ....core.error import BaseError
from ....core.profile import Profile, ProfileSession
from ....storage.base import BaseStorage
from ....storage.error import StorageNotFoundError
from ....storage.record import StorageRecord
from ....wallet.base import BaseWallet, DIDInfo
from ...routing.v1_0.manager import RoutingManager
from ...routing.v1_0.models.route_record import RouteRecord
from ...routing.v1_0.models.route_update import RouteUpdate
from ...routing.v1_0.models.route_updated import RouteUpdated
from .messages.inner.keylist_key import KeylistKey
from .messages.inner.keylist_query_paginate import KeylistQueryPaginate
from .messages.inner.keylist_update_rule import KeylistUpdateRule
from .messages.inner.keylist_updated import KeylistUpdated
from .messages.keylist import Keylist
from .messages.keylist_query import KeylistQuery
from .messages.keylist_update import KeylistUpdate
from .messages.keylist_update_response import KeylistUpdateResponse
from .messages.mediate_deny import MediationDeny
from .messages.mediate_grant import MediationGrant
from .messages.mediate_request import MediationRequest
from .models.mediation_record import MediationRecord

LOGGER = logging.getLogger(__name__)


class MediationManagerError(BaseError):
    """Generic Mediation error."""


class MediationAlreadyExists(MediationManagerError):
    """Raised on mediation record already exists for given connection."""


class MediationNotGrantedError(MediationManagerError):
    """Raised when mediation state should be granted and is not."""


class MediationManager:
    """Class for handling Mediation.

    MediationManager creates or retrieves a routing DID as a means to hand out
    a consistent routing key to mediation clients.
    """

    ROUTING_DID_RECORD_TYPE = "routing_did"
    DEFAULT_MEDIATOR_RECORD_TYPE = "default_mediator"
    SEND_REQ_AFTER_CONNECTION = "send_mediation_request_on_connection"
    SET_TO_DEFAULT_ON_GRANTED = "set_to_default_on_granted"

    def __init__(self, profile: Profile):
        """Initialize Mediation Manager.

        Args:
            profile: The Profile instance for this manager
        """
        self._profile = profile
        if not profile:
            raise MediationManagerError("Missing profile")

    # Role: Server {{{

    async def _retrieve_routing_did(self, session: ProfileSession) -> Optional[DIDInfo]:
        """Retrieve routing DID from the store.

        Args:
            session: An active profile session

        Returns:
            Optional[DIDInfo]: retrieved DID info or None if not found

        """
        storage = session.inject(BaseStorage)
        try:
            record = await storage.get_record(
                record_type=self.ROUTING_DID_RECORD_TYPE,
                record_id=self.ROUTING_DID_RECORD_TYPE,
            )
            info = json.loads(record.value)
            info.update(record.tags)
            return DIDInfo(**info)
        except StorageNotFoundError:
            return None

    async def _create_routing_did(self, session: ProfileSession) -> DIDInfo:
        """Create routing DID.

        Args:
            session: An active profile session

        Returns:
            DIDInfo: created routing DID info

        """
        wallet = session.inject(BaseWallet)
        storage = session.inject(BaseStorage)
        info = await wallet.create_local_did(
            method_name="peer", metadata={"type": "routing_did"}
        )
        record = StorageRecord(
            type=self.ROUTING_DID_RECORD_TYPE,
            value=json.dumps({"verkey": info.verkey, "metadata": info.metadata}),
            tags={"did": info.did},
            id=self.ROUTING_DID_RECORD_TYPE,
        )
        await storage.add_record(record)
        return info

    async def receive_request(
        self, connection_id: str, request: MediationRequest
    ) -> MediationRecord:
        """Create a new mediation record to track this request.

        Args:
            request (MediationRequest): request message

        Returns:
            MediationRecord: record created during receipt of request.

        """
        async with self._profile.session() as session:
            if await MediationRecord.exists_for_connection_id(session, connection_id):
                raise MediationAlreadyExists(
                    "MediationRecord already exists for connection"
                )

            # TODO: Determine if terms are acceptable
            record = MediationRecord(
                connection_id=connection_id,
                mediator_terms=request.mediator_terms,
                recipient_terms=request.recipient_terms,
            )
            await record.save(session, reason="New mediation request received")
        return record

    async def grant_request(
        self, mediation_id: str
    ) -> Tuple[MediationRecord, MediationGrant]:
        """Grant a mediation request and prepare grant message.

        Args:
            mediation_id: mediation record ID to grant

        Returns:
            (MediationRecord, MediationGrant): updated mediation record and message to
            return to grantee

        """
        async with self._profile.session() as session:
            mediation_record = await MediationRecord.retrieve_by_id(
                session, mediation_id
            )
            if mediation_record.role != MediationRecord.ROLE_SERVER:
                raise MediationManagerError(
                    f"role({mediation_record.role}) is not {MediationRecord.ROLE_SERVER}"
                )

            routing_did = await self._retrieve_routing_did(session)
            if not routing_did:
                routing_did = await self._create_routing_did(session)

            mediation_record.state = MediationRecord.STATE_GRANTED

            await mediation_record.save(session, reason="Mediation request granted")
            grant = MediationGrant(
                endpoint=session.settings.get("default_endpoint"),
                routing_keys=[routing_did.verkey],
            )
        return mediation_record, grant

    async def deny_request(
        self,
        mediation_id: str,
        *,
        mediator_terms: Sequence[str] = None,
        recipient_terms: Sequence[str] = None,
    ) -> Tuple[MediationRecord, MediationDeny]:
        """Deny a mediation request and prepare a deny message.

        Args:
            mediation_id: mediation record ID to deny
            mediator_terms (Sequence[str]): updated mediator terms to return to
            requester.
            recipient_terms (Sequence[str]): updated recipient terms to return to
            requester.

        Returns:
            MediationDeny: message to return to denied client.

        """
        async with self._profile.session() as session:
            mediation_record = await MediationRecord.retrieve_by_id(
                session, mediation_id
            )
            if mediation_record.role != MediationRecord.ROLE_SERVER:
                raise MediationManagerError(
                    f"role({mediation_record.role}) is not {MediationRecord.ROLE_SERVER}"
                )

            mediation_record.state = MediationRecord.STATE_DENIED
            await mediation_record.save(session, reason="Mediation request denied")

        deny = MediationDeny(
            mediator_terms=mediator_terms, recipient_terms=recipient_terms
        )
        return mediation_record, deny

    async def update_keylist(
        self, record: MediationRecord, updates: Sequence[KeylistUpdateRule]
    ) -> KeylistUpdateResponse:
        """Update routes defined in keylist update rules.

        Args:
            record (MediationRecord): record associated with client updating keylist
            updates (Sequence[KeylistUpdateRule]): updates to apply

        Returns:
            KeylistUpdateResponse: message to return to client

        """
        if record.state != MediationRecord.STATE_GRANTED:
            raise MediationNotGrantedError(
                "Mediation has not been granted for this connection."
            )
        # TODO: Don't borrow logic from RoutingManager
        # Bidirectional mapping of KeylistUpdateRules to RouteUpdate actions
        action_map = {
            KeylistUpdateRule.RULE_ADD: RouteUpdate.ACTION_CREATE,
            KeylistUpdateRule.RULE_REMOVE: RouteUpdate.ACTION_DELETE,
            RouteUpdate.ACTION_DELETE: KeylistUpdateRule.RULE_REMOVE,
            RouteUpdate.ACTION_CREATE: KeylistUpdateRule.RULE_ADD,
        }

        def rule_to_update(rule: KeylistUpdateRule):
            return RouteUpdate(
                recipient_key=rule.recipient_key, action=action_map[rule.action]
            )

        def updated_to_keylist_updated(updated: RouteUpdated):
            return KeylistUpdated(
                recipient_key=updated.recipient_key,
                action=action_map[updated.action],
                result=updated.result,
            )

        route_mgr = RoutingManager(self._profile)
        # Map keylist update rules to route updates
        updates = map(rule_to_update, updates)
        updated = await route_mgr.update_routes(record.connection_id, updates)
        # Map RouteUpdated to KeylistUpdated
        updated = map(updated_to_keylist_updated, updated)
        return KeylistUpdateResponse(updated=updated)

    async def get_keylist(self, record: MediationRecord) -> Sequence[RouteRecord]:
        """Retrieve keylist for mediation client.

        Args:
            record (MediationRecord): record associated with client keylist

        Returns:
            Sequence[RouteRecord]: sequence of routes (the keylist)

        """
        if record.state != MediationRecord.STATE_GRANTED:
            raise MediationNotGrantedError(
                "Mediation has not been granted for this connection."
            )
        route_mgr = RoutingManager(self._profile)
        return await route_mgr.get_routes(record.connection_id)

    async def create_keylist_query_response(
        self, keylist: Sequence[RouteRecord]
    ) -> Keylist:
        """Prepare a keylist message from keylist.

        Args:
            keylist (Sequence[RouteRecord]): keylist to format into message

        Returns:
            Keylist: message to return to client

        """
        keys = list(
            map(lambda key: KeylistKey(recipient_key=key.recipient_key), keylist)
        )
        return Keylist(keys=keys, pagination=None)

    # }}}

    # Role: Client {{{

    async def _get_default_record(
        self, session: ProfileSession
    ) -> Optional[StorageRecord]:
        """Retrieve the default mediator raw record for use in updating or deleting.

        Args:
            session: An active profile session

        Returns:
            Optional[StorageRecord]: Record if present

        """
        storage = session.inject(BaseStorage)
        try:
            default_record = await storage.get_record(
                record_type=self.DEFAULT_MEDIATOR_RECORD_TYPE,
                record_id=self.DEFAULT_MEDIATOR_RECORD_TYPE,
            )
            return default_record
        except StorageNotFoundError:
            return None

    async def _get_default_mediator_id(self, session: ProfileSession) -> Optional[str]:
        """Retrieve the default mediator's ID from the store.

        Args:
            session: An active profile session

        Returns:
            Optional[str]: ID if present

        """
        default_record = await self._get_default_record(session)
        if default_record:
            return default_record.value

        return None

    async def get_default_mediator(self) -> Optional[MediationRecord]:
        """Retrieve default mediator from the store.

        Returns:
            Optional[MediationRecord]: retrieved default mediator or None if not set

        """
        async with self._profile.session() as session:
            mediation_id = await self._get_default_mediator_id(session)
            if mediation_id:
                return await MediationRecord.retrieve_by_id(session, mediation_id)

        return None

    async def get_default_mediator_id(self) -> Optional[str]:
        """Retrieve default mediator ID from the store.

        Returns:
            Optional[str]: retrieved default mediator ID or None if not set

        """
        async with self._profile.session() as session:
            return await self._get_default_mediator_id(session)

    async def set_default_mediator_by_id(self, mediation_id: str):
        """Set default mediator from ID."""
        async with self._profile.session() as session:
            # may throw StorageNotFoundError:
            await MediationRecord.retrieve_by_id(session, mediation_id)
            await self._set_default_mediator_id(mediation_id, session)

    async def set_default_mediator(self, record: MediationRecord):
        """Set default mediator from record."""
        async with self._profile.session() as session:
            await self._set_default_mediator_id(record.mediation_id, session)

    async def _set_default_mediator_id(
        self, mediation_id: str, session: ProfileSession
    ):
        """Set the default mediator ID (internal)."""
        default_record = await self._get_default_record(session)
        storage = session.inject(BaseStorage)

        if default_record:
            await storage.update_record(default_record, mediation_id, {})
        else:
            default_record = StorageRecord(
                type=self.DEFAULT_MEDIATOR_RECORD_TYPE,
                value=mediation_id,
                id=self.DEFAULT_MEDIATOR_RECORD_TYPE,
            )
            await storage.add_record(default_record)

    async def clear_default_mediator(self):
        """Clear the stored default mediator."""
        async with self._profile.session() as session:
            storage = session.inject(BaseStorage)
            default_record = await self._get_default_record(session)
            if default_record:
                await storage.delete_record(default_record)

    async def prepare_request(
        self,
        connection_id: str,
        mediator_terms: Sequence[str] = None,
        recipient_terms: Sequence[str] = None,
    ) -> Tuple[MediationRecord, MediationRequest]:
        """Prepare a MediationRequest Message, saving a new mediation record.

        Args:
            connection_id (str): ID representing mediator
            mediator_terms (Sequence[str]): mediator_terms
            recipient_terms (Sequence[str]): recipient_terms

        Returns:
            MediationRequest: message to send to mediator

        """
        record = MediationRecord(
            role=MediationRecord.ROLE_CLIENT,
            connection_id=connection_id,
            mediator_terms=mediator_terms,
            recipient_terms=recipient_terms,
        )

        async with self._profile.session() as session:
            await record.save(session, reason="Creating new mediation request.")
        request = MediationRequest(
            mediator_terms=mediator_terms, recipient_terms=recipient_terms
        )
        return record, request

    async def request_granted(self, record: MediationRecord, grant: MediationGrant):
        """Process mediation grant message.

        Args:
            record (MediationRecord): record representing the granted mediation request

        """
        record.state = MediationRecord.STATE_GRANTED
        record.endpoint = grant.endpoint
        record.routing_keys = grant.routing_keys
        async with self._profile.session() as session:
            await record.save(session, reason="Mediation request granted.")

    async def request_denied(self, record: MediationRecord, deny: MediationDeny):
        """Process mediation denied message.

        Args:
            record (MediationRecord): record representing the denied mediation request

        """
        record.state = MediationRecord.STATE_DENIED
        # TODO Record terms elsewhere?
        record.mediator_terms = deny.mediator_terms
        record.recipient_terms = deny.recipient_terms
        async with self._profile.session() as session:
            await record.save(session, reason="Mediation request denied.")

    async def prepare_keylist_query(
        self, filter_: dict = None, paginate_limit: int = -1, paginate_offset: int = 0
    ) -> KeylistQuery:
        """Prepare keylist query message.

        Args:
            filter_ (dict): filter for keylist query
            paginate_limit (int): paginate_limit
            paginate_offset (int): paginate_offset

        Returns:
            KeylistQuery: message to send to mediator

        """
        # TODO Handle creation of filter rather than delegating to caller?
        message = KeylistQuery(
            filter=filter_,
            paginate=KeylistQueryPaginate(paginate_limit, paginate_offset),
        )
        return message

    async def add_key(
        self, recipient_key: str, message: Optional[KeylistUpdate] = None
    ) -> KeylistUpdate:
        """Prepare a keylist update add.

        Args:
            recipient_key (str): key to add
            message (Optional[KeylistUpdate]): append update to message

        Returns:
            KeylistUpdate: Message to send to mediator to notify of key addition.

        """
        message = message or KeylistUpdate()
        message.updates.append(
            KeylistUpdateRule(recipient_key, KeylistUpdateRule.RULE_ADD)
        )
        return message

    async def remove_key(
        self, recipient_key: str, message: Optional[KeylistUpdate] = None
    ) -> KeylistUpdate:
        """Prepare keylist update remove.

        Args:
            recipient_key (str): key to remove
            message (Optional[KeylistUpdate]): append update to message

        Returns:
            KeylistUpdate: Message to send to mediator to notify of key removal.

        """
        message = message or KeylistUpdate()
        message.updates.append(
            KeylistUpdateRule(recipient_key, KeylistUpdateRule.RULE_REMOVE)
        )
        return message

    async def store_update_results(
        self, connection_id: str, results: Sequence[KeylistUpdated]
    ):
        """Store results of keylist update from keylist update response message.

        Args:
            connection_id (str): connection ID of mediator sending results
            results (Sequence[KeylistUpdated]): keylist update results
            session: An active profile session

        """
        session = await self._profile.session()
        to_save: Sequence[RouteRecord] = []
        to_remove: Sequence[RouteRecord] = []
        for updated in results:
            if updated.result != KeylistUpdated.RESULT_SUCCESS:
                # TODO better handle different results?
                LOGGER.warning(
                    "Keylist update failure: %s(%s): %s",
                    updated.action,
                    updated.recipient_key,
                    updated.result,
                )
                continue
            if updated.action == KeylistUpdateRule.RULE_ADD:
                # Multi-tenancy uses route record for internal relaying of wallets
                # So the record could already exist. We update in that case
                try:
                    record = await RouteRecord.retrieve_by_recipient_key(
                        session, updated.recipient_key
                    )
                    record.connection_id = connection_id
                    record.role = RouteRecord.ROLE_CLIENT
                except StorageNotFoundError:
                    record = RouteRecord(
                        role=RouteRecord.ROLE_CLIENT,
                        recipient_key=updated.recipient_key,
                        connection_id=connection_id,
                    )
                to_save.append(record)
            elif updated.action == KeylistUpdateRule.RULE_REMOVE:
                try:
                    records = await RouteRecord.query(
                        session,
                        {
                            "role": RouteRecord.ROLE_CLIENT,
                            "connection_id": connection_id,
                            "recipient_key": updated.recipient_key,
                        },
                    )
                except StorageNotFoundError as err:
                    LOGGER.error(
                        "No route found while processing keylist update response: %s",
                        err,
                    )
                else:
                    if len(records) > 1:
                        LOGGER.error(
                            f"Too many ({len(records)}) routes found "
                            "while processing keylist update response"
                        )
                    record = records[0]
                    to_remove.append(record)

        for record_for_saving in to_save:
            await record_for_saving.save(session, reason="Route successfully added.")
        for record_for_removal in to_remove:
            await record_for_removal.delete_record(session)

    async def get_my_keylist(
        self, connection_id: Optional[str] = None
    ) -> Sequence[RouteRecord]:
        """Get my routed keys.

        Args:
            connection_id (Optional[str]): connection id of mediator

        Returns:
            Sequence[RouteRecord]: list of routes (the keylist)

        """
        # TODO use mediation record id instead of connection id?
        tag_filter = {"connection_id": connection_id} if connection_id else {}
        tag_filter["role"] = RouteRecord.ROLE_CLIENT
        async with self._profile.session() as session:
            return await RouteRecord.query(session, tag_filter)

    # }}}
