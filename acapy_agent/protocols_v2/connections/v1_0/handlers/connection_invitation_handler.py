"""Connect invitation handler."""

from .....messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from ..messages.connection_invitation import ConnectionInvitation
from ..messages.problem_report import ConnectionProblemReport, ProblemReportReason


class ConnectionInvitationHandler(BaseHandler):
    """Handler class for connection invitations."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle connection invitation.

        Args:
            context: Request context
            responder: Responder callback
        """

        self._logger.debug(f"ConnectionInvitationHandler called with context {context}")
        assert isinstance(context.message, ConnectionInvitation)

        report = ConnectionProblemReport(
            description={
                "code": ProblemReportReason.INVITATION_NOT_ACCEPTED.value,
                "en": ("Connection invitations cannot be submitted via agent messaging"),
            }
        )
        report.assign_thread_from(context.message)
        # client likely needs to be using direct responses to receive the problem report
        await responder.send_reply(report)
