"""Message type identifiers for Trust Pings."""

import logging
from ....messaging.v2_agent_message import V2AgentMessage

SPEC_URI = "https://didcomm.org/discover-features/2.0/queries"

# Message types
QUERIES = "https://didcomm.org/discover-features/2.0/queries"
DISCLOSE = "https://didcomm.org/discover-features/2.0/disclose"

PROTOCOL_PACKAGE = "acapy_agent.protocols_v2.discovery.v1_0"

BASIC_MESSAGE = "https://didcomm.org/basicmessage/2.0/message"
EMPTY = "https://didcomm.org/empty/1.0/empty"
PING = "https://didcomm.org/trust-ping/2.0/ping"


class discover_features:
    """Discover Features 2.0 DIDComm V2 Protocol."""

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
                "type": DISCLOSE,
                "thid": payload["id"],
                "body": {
                    "disclosures": [
                        {
                            "feature-type": "protocol",
                            "id": protocol.rsplit("/", 1)[0],
                        }
                        for protocol in [PING, BASIC_MESSAGE, QUERIES, EMPTY]
                    ],
                },
                "to": [their_did],
                "from": our_did,
            }
        )
        await responder.send_reply(error_result)


HANDLERS = {
    QUERIES: f"{PROTOCOL_PACKAGE}.message_types.discover_features",
}.items()

MESSAGE_TYPES = {
    QUERIES: f"{PROTOCOL_PACKAGE}.message_types.discover_features",
}
