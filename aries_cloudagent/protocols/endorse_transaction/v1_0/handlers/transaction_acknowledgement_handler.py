"""Transaction acknowledgement message handler."""

from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ..manager import TransactionManager, TransactionManagerError
from ..messages.transaction_acknowledgement import TransactionAcknowledgement


class TransactionAcknowledgementHandler(BaseHandler):
    """Message handler class for Acknowledging transaction."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Handle transaction acknowledgement message.

        Args:
            context: Request context
            responder: Responder callback
        """

        self._logger.debug(
            f"TransactionAcknowledgementHandler called with context {context}"
        )
        assert isinstance(context.message, TransactionAcknowledgement)

        if not context.connection_ready:
            raise HandlerException("No connection established")

        profile_session = await context.session()
        mgr = TransactionManager(profile_session)
        try:
            await mgr.receive_transaction_acknowledgement(
                context.message, context.connection_record.connection_id
            )
        except TransactionManagerError:
            self._logger.exception("Error receiving transaction acknowledgement")
