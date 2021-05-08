"""Credential ack message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

from ..manager import V20CredManager
from ..messages.cred_ack import V20CredAck

from .....utils.tracing import trace_event, get_timer


class V20CredAckHandler(BaseHandler):
    """Message handler class for credential acks."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential acks.

        Args:
            context: request context
            responder: responder callback
        """
        r_time = get_timer()

        self._logger.debug("V20CredAckHandler called with context %s", context)
        assert isinstance(context.message, V20CredAck)
        self._logger.info(
            "Received v2.0 credential ack message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential ack")

        cred_manager = V20CredManager(context.profile)
        await cred_manager.receive_credential_ack(
            context.message, context.connection_record.connection_id
        )

        trace_event(
            context.settings,
            context.message,
            outcome="V20CredAckHandler.handle.END",
            perf_counter=r_time,
        )
