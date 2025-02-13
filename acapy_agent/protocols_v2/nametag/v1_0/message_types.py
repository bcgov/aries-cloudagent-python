"""Message type identifiers for Trust Pings."""

import logging
from ....messaging.v2_agent_message import V2AgentMessage

SPEC_URI = "https://didcomm.org/basicmessage/2.0/message"

# Message types
BASIC_MESSAGE = "https://colton.wolkins.net/dev/name-tag/2.0/get-name"

PROTOCOL_PACKAGE = "acapy_agent.protocols_v2.nametag.v1_0"


class basic_message:
    """Basic Message 2.0 DIDComm V2 Protocol."""

    async def __call__(self, *args, **kwargs):
        """Call the Handler."""
        await self.handle(*args, **kwargs)

    @staticmethod
    async def handle(context, responder, payload):
        """Handle the incoming message."""
        logging.getLogger(__name__)
        their_did = context.message_receipt.sender_verkey.split("#")[0]
        our_did = context.message_receipt.recipient_verkey.split("#")[0]
        error_result = V2AgentMessage(
            message={
                "type": BASIC_MESSAGE,
                "body": {
                    "content": "Hello from acapy",
                },
                "to": [their_did],
                "from": our_did,
                "lang": "en",
            }
        )
        await responder.send_reply(error_result)


HANDLERS = {
    BASIC_MESSAGE: f"{PROTOCOL_PACKAGE}.message_types.basic_message",
}.items()

MESSAGE_TYPES = {
    BASIC_MESSAGE: f"{PROTOCOL_PACKAGE}.message_types.basic_message",
}
