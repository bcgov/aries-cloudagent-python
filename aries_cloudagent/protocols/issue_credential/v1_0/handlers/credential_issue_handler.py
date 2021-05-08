"""Credential issue message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

from ..manager import CredentialManager
from ..messages.credential_issue import CredentialIssue

from .....utils.tracing import trace_event, get_timer


class CredentialIssueHandler(BaseHandler):
    """Message handler class for credential offers."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential offers.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("CredentialHandler called with context %s", context)
        assert isinstance(context.message, CredentialIssue)
        self._logger.info(
            "Received credential message: %s", context.message.serialize(as_string=True)
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential issue")

        credential_manager = CredentialManager(context.profile)
        cred_ex_record = await credential_manager.receive_credential(
            context.message, context.connection_record.connection_id
        )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="CredentialIssueHandler.handle.END",
            perf_counter=r_time,
        )

        # Automatically move to next state if flag is set
        if context.settings.get("debug.auto_store_credential"):
            (
                cred_ex_record,
                credential_ack_message,
            ) = await credential_manager.store_credential(cred_ex_record)

            # Ack issuer that holder stored credential
            await responder.send_reply(credential_ack_message)

            trace_event(
                context.settings,
                credential_ack_message,
                outcome="CredentialIssueHandler.handle.STORE",
                perf_counter=r_time,
            )
