"""Message type identifiers for Trust Pings."""

import logging

SPEC_URI = "https://identity.foundation/didcomm-messaging/spec/v2.1/#the-empty-message"

# Message types
EMPTY = "https://didcomm.org/empty/1.0/empty"

PROTOCOL_PACKAGE = "acapy_agent.protocols_v2.empty.v1_0"


class basic_message:
    """Empty 1.0 DIDComm V2 Protocol."""

    async def __call__(self, *args, **kwargs):
        """Call the Handler."""
        await self.handle(*args, **kwargs)

    @staticmethod
    async def handle(context, responder, payload):
        """Handle the incoming message."""
        logger = logging.getLogger(__name__)
        logger.trace("Received empty message")


HANDLERS = {
    EMPTY: f"{PROTOCOL_PACKAGE}.message_types.empty",
}.items()

MESSAGE_TYPES = {
    EMPTY: f"{PROTOCOL_PACKAGE}.message_types.empty",
}
