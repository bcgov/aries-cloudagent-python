"""Presentation proposal message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from .....utils.tracing import trace_event, get_timer

from ..manager import V20PresManager
from ..messages.pres_proposal import V20PresProposal


class V20PresProposalHandler(BaseHandler):
    """Message handler class for presentation proposals."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for presentation proposals.

        Args:
            context: proposal context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("V20PresProposalHandler called with context %s", context)
        assert isinstance(context.message, V20PresProposal)
        self._logger.info(
            "Received v2.0 presentation proposal message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException(
                "No connection established for presentation proposal"
            )

        pres_manager = V20PresManager(context.profile)
        pres_ex_record = await pres_manager.receive_pres_proposal(
            context.message, context.connection_record
        )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="V20PresProposalHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto_respond_presentation_proposal is set, reply with proof req
        if context.settings.get("debug.auto_respond_presentation_proposal"):
            (
                pres_ex_record,
                pres_request_message,
            ) = await pres_manager.create_bound_request(
                pres_ex_record=pres_ex_record,
                comment=context.message.comment,
            )

            await responder.send_reply(pres_request_message)

            trace_event(
                context.settings,
                pres_request_message,
                outcome="V20PresProposalHandler.handle.PRESENT",
                perf_counter=r_time,
            )
