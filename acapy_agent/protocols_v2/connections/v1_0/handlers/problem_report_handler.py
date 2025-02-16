"""Problem report handler for Connection Protocol."""

from .....connections.models.conn_record import ConnRecord
from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)
from .....storage.error import StorageNotFoundError
from ..manager import ConnectionManager, ConnectionManagerError
from ..messages.problem_report import ConnectionProblemReport


class ConnectionProblemReportHandler(BaseHandler):
    """Handler class for Connection problem report messages."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle problem report message."""
        self._logger.debug(
            f"ConnectionProblemReportHandler called with context {context}"
        )
        assert isinstance(context.message, ConnectionProblemReport)

        self._logger.info(f"Received problem report: {context.message.problem_code}")
        profile = context.profile
        mgr = ConnectionManager(profile)
        try:
            conn_rec = context.connection_record
            if not conn_rec:
                # try to find connection by thread_id/request_id
                try:
                    async with profile.session() as session:
                        conn_rec = await ConnRecord.retrieve_by_request_id(
                            session, context.message._thread_id
                        )
                except StorageNotFoundError:
                    pass

            if conn_rec:
                await mgr.receive_problem_report(conn_rec, context.message)
            else:
                raise HandlerException("No connection established for problem report")
        except ConnectionManagerError:
            # Unrecognized problem report code
            self._logger.exception("Error receiving Connection problem report")
