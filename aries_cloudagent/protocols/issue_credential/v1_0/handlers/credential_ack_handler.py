"""Credential ack message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

from ..manager import CredentialManager
from ..messages.credential_ack import CredentialAck

from .....utils.tracing import trace_event, get_timer


class CredentialAckHandler(BaseHandler):
    """Message handler class for credential acks."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential acks.

        Args:
            context: request context
            responder: responder callback
        """
        r_time = get_timer()

        self._logger.debug("CredentialAckHandler called with context %s", context)
        assert isinstance(context.message, CredentialAck)
        self._logger.info(
            "Received credential ack message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential ack")

        credential_manager = CredentialManager(context.profile)
        await credential_manager.receive_credential_ack(
            context.message, context.connection_record.connection_id
        )

        trace_event(
            context.settings,
            context.message,
            outcome="CredentialAckHandler.handle.END",
            perf_counter=r_time,
        )
