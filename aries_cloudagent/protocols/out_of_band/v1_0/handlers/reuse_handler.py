"""Handshake Reuse Message Handler under RFC 0434."""

from .....config.logging import get_adapted_logger_inst
from .....messaging.base_handler import BaseHandler
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

from ..manager import OutOfBandManager, OutOfBandManagerError
from ..messages.reuse import HandshakeReuse


class HandshakeReuseMessageHandler(BaseHandler):
    """Handler class for Handshake Reuse Message Handler under RFC 0434."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle Handshake Reuse Message Handler under RFC 0434.

        Args:
            context: Request context
            responder: Responder callback
        """
        profile = context.profile
        self._logger = get_adapted_logger_inst(
            logger=self._logger,
            log_file=profile.settings.get("log.file"),
            wallet_id=profile.settings.get("wallet.id"),
        )
        self._logger.debug(
            f"HandshakeReuseMessageHandler called with context {context}"
        )
        assert isinstance(context.message, HandshakeReuse)

        mgr = OutOfBandManager(profile)
        try:
            await mgr.receive_reuse_message(
                context.message, context.message_receipt, context.connection_record
            )
        except OutOfBandManagerError as e:
            self._logger.exception(f"Error processing Handshake Reuse message, {e}")
