"""Presentation message handler."""

from .....messaging.base_handler import BaseHandler
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from .....utils.tracing import trace_event, get_timer

from ..manager import V20PresManager
from ..messages.pres import V20Pres


class V20PresHandler(BaseHandler):
    """Message handler class for presentations."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for presentations.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("V20PresHandler called with context %s", context)
        assert isinstance(context.message, V20Pres)
        self._logger.info(
            "Received presentation message: %s",
            context.message.serialize(as_string=True),
        )

        pres_manager = V20PresManager(context.profile)

        pres_ex_record = await pres_manager.receive_pres(
            context.message, context.connection_record
        )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="V20PresHandler.handle.END",
            perf_counter=r_time,
        )

        if context.settings.get("debug.auto_verify_presentation"):
            await pres_manager.verify_pres(pres_ex_record)

            trace_event(
                context.settings,
                pres_ex_record,
                outcome="V20PresHandler.handle.VERIFY",
                perf_counter=r_time,
            )
