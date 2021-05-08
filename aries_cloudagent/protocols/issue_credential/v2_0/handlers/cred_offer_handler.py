"""Credential offer message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

from ..manager import V20CredManager
from ..messages.cred_offer import V20CredOffer

from .....utils.tracing import trace_event, get_timer


class V20CredOfferHandler(BaseHandler):
    """Message handler class for credential offers."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential offers.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("V20CredOfferHandler called with context %s", context)
        assert isinstance(context.message, V20CredOffer)
        self._logger.info(
            "Received v2.0 credential offer message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential offer")

        cred_manager = V20CredManager(context.profile)
        cred_ex_record = await cred_manager.receive_offer(
            context.message, context.connection_record.connection_id
        )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="V20CredOfferHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto respond is turned on, automatically reply with credential request
        if context.settings.get("debug.auto_respond_credential_offer"):
            (_, cred_request_message) = await cred_manager.create_request(
                cred_ex_record=cred_ex_record,
                holder_did=context.connection_record.my_did,
            )
            await responder.send_reply(cred_request_message)

            trace_event(
                context.settings,
                cred_request_message,
                outcome="V20CredOfferHandler.handle.REQUEST",
                perf_counter=r_time,
            )
