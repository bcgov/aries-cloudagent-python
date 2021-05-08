"""Credential proposal message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

from ..manager import V20CredManager
from ..messages.cred_proposal import V20CredProposal

from .....utils.tracing import trace_event, get_timer


class V20CredProposalHandler(BaseHandler):
    """Message handler class for credential proposals."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential proposals.

        Args:
            context: proposal context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("V20CredProposalHandler called with context %s", context)
        assert isinstance(context.message, V20CredProposal)
        self._logger.info(
            "Received v2.0 credential proposal message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential proposal")

        cred_manager = V20CredManager(context.profile)
        cred_ex_record = await cred_manager.receive_proposal(
            context.message, context.connection_record.connection_id
        )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="CredentialProposalHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto_offer is enabled, respond immediately with offer
        if cred_ex_record.auto_offer:
            (cred_ex_record, cred_offer_message) = await cred_manager.create_offer(
                cred_ex_record,
                counter_proposal=None,
                comment=context.message.comment,
            )

            await responder.send_reply(cred_offer_message)

            trace_event(
                context.settings,
                cred_offer_message,
                outcome="V20CredProposalHandler.handle.OFFER",
                perf_counter=r_time,
            )
