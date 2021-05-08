"""Credential issue message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

from ..manager import V20CredManager
from ..messages.cred_issue import V20CredIssue

from .....utils.tracing import trace_event, get_timer


class V20CredIssueHandler(BaseHandler):
    """Message handler class for credential offers."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential offers.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("V20CredIssueHandler called with context %s", context)
        assert isinstance(context.message, V20CredIssue)
        self._logger.info(
            "Received v2.0 credential issue message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential issue")

        cred_manager = V20CredManager(context.profile)
        cred_ex_record = await cred_manager.receive_credential(
            context.message, context.connection_record.connection_id
        )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="V20CredIssueHandler.handle.END",
            perf_counter=r_time,
        )

        # Automatically move to next state if flag is set
        if context.settings.get("debug.auto_store_credential"):
            (
                cred_ex_record,
                cred_ack_message,
            ) = await cred_manager.store_credential(cred_ex_record)

            if cred_ex_record.auto_remove:
                await cred_manager.delete_cred_ex_record(cred_ex_record.cred_ex_id)

            # Ack issuer that holder stored credential
            await responder.send_reply(cred_ack_message)

            trace_event(
                context.settings,
                cred_ack_message,
                outcome="V20CredIssueHandler.handle.STORE",
                perf_counter=r_time,
            )
