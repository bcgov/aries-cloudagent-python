"""Connection request handler."""

from .....connections.models.conn_record import ConnRecord
from .....messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from ....coordinate_mediation.v1_0.manager import MediationManager
from ..manager import ConnectionManager, ConnectionManagerError
from ..messages.connection_request import ConnectionRequest


class ConnectionRequestHandler(BaseHandler):
    """Handler class for connection requests."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle connection request.

        Args:
            context: Request context
            responder: Responder callback
        """

        self._logger.debug(f"ConnectionRequestHandler called with context {context}")
        assert isinstance(context.message, ConnectionRequest)

        profile = context.profile
        mgr = ConnectionManager(profile)

        mediation_id = None
        if context.connection_record:
            async with profile.session() as session:
                mediation_metadata = await context.connection_record.metadata_get(
                    session, MediationManager.METADATA_KEY, {}
                )
            mediation_id = mediation_metadata.get(MediationManager.METADATA_ID)

        try:
            connection = await mgr.receive_request(
                context.message,
                context.message_receipt,
            )

            if connection.accept == ConnRecord.ACCEPT_AUTO:
                response = await mgr.create_response(
                    connection, mediation_id=mediation_id
                )
                await responder.send_reply(
                    response, connection_id=connection.connection_id
                )
            else:
                self._logger.debug("Connection request will await acceptance")
        except ConnectionManagerError as e:
            report, targets = mgr.manager_error_to_problem_report(
                e, context.message, context.message_receipt
            )
            if report and targets:
                await responder.send_reply(
                    message=report,
                    target_list=targets,
                )
