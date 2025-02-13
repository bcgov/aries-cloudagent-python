"""Connection response handler."""

from .....messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from .....protocols.trustping.v1_0.messages.ping import Ping
from ..manager import ConnectionManager, ConnectionManagerError
from ..messages.connection_response import ConnectionResponse


class ConnectionResponseHandler(BaseHandler):
    """Handler class for connection responses."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle connection response.

        Args:
            context: Request context
            responder: Responder callback
        """
        self._logger.debug(f"ConnectionResponseHandler called with context {context}")
        assert isinstance(context.message, ConnectionResponse)

        profile = context.profile
        mgr = ConnectionManager(profile)
        try:
            connection = await mgr.accept_response(
                context.message, context.message_receipt
            )
        except ConnectionManagerError as e:
            report, targets = mgr.manager_error_to_problem_report(
                e, context.message, context.message_receipt
            )
            if report and targets:
                await responder.send_reply(
                    message=report,
                    target_list=targets,
                )
            return

        # send trust ping in response
        if context.settings.get("auto_ping_connection"):
            (await responder.send(Ping(), connection_id=connection.connection_id),)
