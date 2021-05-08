"""Presentation problem report message handler."""

from .....messaging.base_handler import BaseHandler
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from .....storage.error import StorageError, StorageNotFoundError

from ..manager import PresentationManager
from ..messages.presentation_problem_report import PresentationProblemReport


class PresentationProblemReportHandler(BaseHandler):
    """Message handler class for problem reports."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for problem reports.

        Args:
            context: request context
            responder: responder callback
        """
        self._logger.debug(
            "Present-proof v1.0 problem report handler called with context %s",
            context,
        )
        assert isinstance(context.message, PresentationProblemReport)

        presentation_manager = PresentationManager(context.profile)
        try:
            await presentation_manager.receive_problem_report(
                context.message,
                context.connection_record.connection_id,
            )
        except (StorageError, StorageNotFoundError):
            self._logger.exception(
                "Error processing present-proof v1.0 problem report message"
            )
