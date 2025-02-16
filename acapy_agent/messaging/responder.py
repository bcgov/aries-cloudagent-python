"""A message responder.

The responder is provided to message handlers to enable them to send a new message
in response to the message being handled.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from typing import List, Optional, Sequence, Tuple, Union

from ..cache.base import BaseCache
from ..connections.models.conn_record import ConnRecord
from ..connections.models.connection_target import ConnectionTarget
from ..core.error import BaseError
from ..core.profile import Profile
from ..transport.outbound.message import OutboundMessage
from ..transport.outbound.status import OutboundSendStatus
from .base_message import BaseMessage

SKIP_ACTIVE_CONN_CHECK_MSG_TYPES = [
    "didexchange/1.1/request",
    "didexchange/1.1/response",
    "didexchange/1.1/problem_report",
    "didexchange/1.0/request",
    "didexchange/1.0/response",
    "didexchange/1.0/problem_report",
    "connections/1.0/invitation",
    "connections/1.0/request",
    "connections/1.0/response",
    "connections/1.0/problem_report",
]


class ResponderError(BaseError):
    """Responder error."""


class BaseResponder(ABC):
    """Interface for message handlers to send responses."""

    def __init__(
        self,
        *,
        connection_id: Optional[str] = None,
        reply_session_id: Optional[str] = None,
        reply_to_verkey: Optional[str] = None,
        target: Optional[ConnectionTarget] = None,
        target_list: Sequence[ConnectionTarget] = None,
    ):
        """Initialize a base responder."""
        self.connection_id = connection_id
        self.reply_session_id = reply_session_id
        self.reply_to_verkey = reply_to_verkey
        self.target_list = target_list

    async def create_outbound(
        self,
        message: Union[BaseMessage, str, bytes],
        *,
        connection_id: Optional[str] = None,
        reply_session_id: Optional[str] = None,
        reply_thread_id: Optional[str] = None,
        reply_to_verkey: Optional[str] = None,
        reply_from_verkey: Optional[str] = None,
        target: Optional[ConnectionTarget] = None,
        target_list: Sequence[ConnectionTarget] = None,
        to_session_only: bool = False,
    ) -> OutboundMessage:
        """Create an OutboundMessage from a message payload."""
        if isinstance(message, BaseMessage):
            # TODO DIDComm version selection
            serialized = message.serialize()
            # TODO serialized format selection?
            payload = json.dumps(serialized)
            enc_payload = None
            if not reply_thread_id:
                reply_thread_id = message._thread_id
        else:
            payload = None
            enc_payload = message
        return OutboundMessage(
            connection_id=connection_id,
            enc_payload=enc_payload,
            payload=payload,
            reply_session_id=reply_session_id,
            reply_thread_id=reply_thread_id,
            reply_to_verkey=reply_to_verkey,
            reply_from_verkey=reply_from_verkey,
            target=target,
            target_list=target_list,
            to_session_only=to_session_only,
        )

    async def send(
        self, message: Union[BaseMessage, str, bytes], **kwargs
    ) -> OutboundSendStatus:
        """Convert a message to an OutboundMessage and send it."""
        outbound = await self.create_outbound(message, **kwargs)
        if isinstance(message, BaseMessage):
            msg_type = message._message_type
            msg_id = message._id
        else:
            msg_dict = json.loads(message)
            msg_type = msg_dict.get("@type")
            msg_id = msg_dict.get("@id")
        return await self.send_outbound(
            message=outbound,
            message_type=msg_type,
            message_id=msg_id,
        )

    async def send_reply(
        self,
        message: Union[BaseMessage, str, bytes],
        *,
        connection_id: Optional[str] = None,
        target: Optional[ConnectionTarget] = None,
        target_list: Sequence[ConnectionTarget] = None,
    ) -> OutboundSendStatus:
        """Send a reply to an incoming message.

        Args:
            message: the `BaseMessage`, or pre-packed str or bytes to reply with
            connection_id: optionally override the target connection ID
            target: optionally specify a `ConnectionTarget` to send to
            target_list: optionally specify a list of `ConnectionTarget` to send to

        Raises:
            ResponderError: If there is no active connection

        """
        outbound = await self.create_outbound(
            message,
            connection_id=connection_id or self.connection_id,
            reply_session_id=self.reply_session_id,
            reply_to_verkey=self.reply_to_verkey,
            target=target,
            target_list=target_list or self.target_list,
        )
        if isinstance(message, BaseMessage):
            msg_type = message._message_type
            msg_id = message._id
        else:
            msg_dict = json.loads(message)
            msg_type = msg_dict.get("@type")
            msg_id = msg_dict.get("@id")
        return await self.send_outbound(
            message=outbound, message_type=msg_type, message_id=msg_id
        )

    async def conn_rec_active_state_check(
        self, profile: Profile, connection_id: str, timeout: int = 7
    ) -> bool:
        """Check if the connection record is ready for sending outbound message."""

        async def _wait_for_state() -> Tuple[bool, Optional[str]]:
            while True:
                async with profile.session() as session:
                    conn_record = await ConnRecord.retrieve_by_id(session, connection_id)
                    if conn_record.is_ready:
                        # if ConnRecord.State.get(conn_record.state) in (
                        #     ConnRecord.State.COMPLETED,
                        # ):
                        return (True, conn_record.state)
                    await asyncio.sleep(1)

        try:
            cache_key = f"conn_rec_state::{connection_id}"
            connection_state = None
            cache = profile.inject_or(BaseCache)
            if cache:
                connection_state = await cache.get(cache_key)
            if connection_state and ConnRecord.State.get(connection_state) in (
                ConnRecord.State.COMPLETED,
                ConnRecord.State.RESPONSE,
            ):
                return True
            check_flag, connection_state = await asyncio.wait_for(
                _wait_for_state(), timeout
            )
            if cache and connection_state:
                await cache.set(cache_key, connection_state)
            return check_flag
        except asyncio.TimeoutError:
            return False

    @abstractmethod
    async def send_outbound(
        self, message: OutboundMessage, **kwargs
    ) -> OutboundSendStatus:
        """Send an outbound message.

        Args:
            message: The `OutboundMessage` to be sent
            kwargs: Additional keyword arguments
        """

    @abstractmethod
    async def send_webhook(self, topic: str, payload: dict):
        """Dispatch a webhook. DEPRECATED: use the event bus instead.

        Args:
            topic: the webhook topic identifier
            payload: the webhook payload value
        """


class MockResponder(BaseResponder):
    """Mock responder implementation for use by tests."""

    def __init__(self):
        """Initialize the mock responder."""
        self.messages: List[
            Tuple[Union[BaseMessage, str, bytes, OutboundMessage], Optional[dict]]
        ] = []

    async def send(
        self, message: Union[BaseMessage, str, bytes], **kwargs
    ) -> OutboundSendStatus:
        """Convert a message to an OutboundMessage and send it."""
        self.messages.append((message, kwargs))
        return OutboundSendStatus.QUEUED_FOR_DELIVERY

    async def send_reply(
        self, message: Union[BaseMessage, str, bytes], **kwargs
    ) -> OutboundSendStatus:
        """Send a reply to an incoming message."""
        self.messages.append((message, kwargs))
        return OutboundSendStatus.QUEUED_FOR_DELIVERY

    async def send_outbound(
        self, message: OutboundMessage, **kwargs
    ) -> OutboundSendStatus:
        """Send an outbound message."""
        self.messages.append((message, None))
        return OutboundSendStatus.QUEUED_FOR_DELIVERY

    async def send_webhook(self, topic: str, payload: dict):
        """Send an outbound message."""
        raise Exception(
            "responder.send_webhook is deprecated; please use the event bus instead."
        )
