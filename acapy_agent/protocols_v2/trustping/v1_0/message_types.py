"""Message type identifiers for Trust Pings."""

import logging
from ....messaging.v2_agent_message import V2AgentMessage

SPEC_URI = "https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20"

# Message types
PING = "https://didcomm.org/trust-ping/2.0/ping"
PING_RESPONSE = "https://didcomm.org/trust-ping/2.0/ping-response"

PROTOCOL_PACKAGE = "acapy_agent.protocols_v2.trustping.v1_0"


class trust_ping:
    """Trust Ping 2.0 DIDComm V2 Protocol."""

    async def __call__(self, *args, **kwargs):
        """Call the Handler."""
        await self.handle(*args, **kwargs)

    @staticmethod
    async def handle(context, responder, payload):
        """Handle the incoming message."""
        logging.getLogger(__name__)
        if not payload["body"].get("response_requested", False):
            return
        their_did = context.message_receipt.sender_verkey.split("#")[0]
        our_did = context.message_receipt.recipient_verkey.split("#")[0]
        error_result = V2AgentMessage(
            message={
                "type": "https://didcomm.org/trust-ping/2.0/ping-response",
                "thid": payload["id"],
                "body": {},
                "to": [their_did],
                "from": our_did,
            }
        )
        await responder.send_reply(error_result)


HANDLERS = {
    PING: f"{PROTOCOL_PACKAGE}.message_types.trust_ping",
}.items()

MESSAGE_TYPES = {
    PING: f"{PROTOCOL_PACKAGE}.message_types.trust_ping",
}
