"""Presentation problem report message handler."""

from .....messaging.base_handler import BaseHandler
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from .....storage.error import StorageError, StorageNotFoundError

from ..manager import V20PresManager
from ..messages.pres_problem_report import V20PresProblemReport


class V20PresProblemReportHandler(BaseHandler):
    """Message handler class for problem reports."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for problem reports.

        Args:
            context: request context
            responder: responder callback
        """
        self._logger.debug(
            "Present-proof v2.0 problem report handler called with context %s",
            context,
        )
        assert isinstance(context.message, V20PresProblemReport)

        pres_manager = V20PresManager(context.profile)
        try:
            await pres_manager.receive_problem_report(
                context.message,
                context.connection_record.connection_id,
            )
        except (StorageError, StorageNotFoundError):
            self._logger.exception(
                "Error processing present-proof v2.0 problem report message"
            )
