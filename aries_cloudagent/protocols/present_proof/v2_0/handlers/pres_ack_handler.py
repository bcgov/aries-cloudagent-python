"""Presentation ack message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from .....utils.tracing import trace_event, get_timer

from ..manager import V20PresManager
from ..messages.pres_ack import V20PresAck


class V20PresAckHandler(BaseHandler):
    """Message handler class for presentation acks."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for presentation acks.

        Args:
            context: request context
            responder: responder callback
        """
        r_time = get_timer()

        self._logger.debug("V20PresAckHandler called with context %s", context)
        assert isinstance(context.message, V20PresAck)
        self._logger.info(
            "Received v2.0 presentation ack message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for presentation ack")

        pres_manager = V20PresManager(context.profile)
        await pres_manager.receive_pres_ack(context.message, context.connection_record)

        trace_event(
            context.settings,
            context.message,
            outcome="V20PresAckHandler.handle.END",
            perf_counter=r_time,
        )
