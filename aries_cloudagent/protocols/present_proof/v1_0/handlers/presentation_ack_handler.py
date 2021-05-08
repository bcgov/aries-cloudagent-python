"""Presentation ack message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from .....utils.tracing import trace_event, get_timer

from ..manager import PresentationManager
from ..messages.presentation_ack import PresentationAck


class PresentationAckHandler(BaseHandler):
    """Message handler class for presentation acks."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for presentation acks.

        Args:
            context: request context
            responder: responder callback
        """
        r_time = get_timer()

        self._logger.debug("PresentationAckHandler called with context %s", context)
        assert isinstance(context.message, PresentationAck)
        self._logger.info(
            "Received presentation ack message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for presentation ack")

        presentation_manager = PresentationManager(context.profile)
        await presentation_manager.receive_presentation_ack(
            context.message, context.connection_record
        )

        trace_event(
            context.settings,
            context.message,
            outcome="PresentationAckHandler.handle.END",
            perf_counter=r_time,
        )
