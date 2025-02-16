"""Message type identifiers for Connections."""

from ....protocols.didcomm_prefix import DIDCommPrefix

SPEC_URI = (
    "https://github.com/hyperledger/aries-rfcs/tree/"
    "9b0aaa39df7e8bd434126c4b33c097aae78d65bf/features/0160-connection-protocol"
)
ARIES_PROTOCOL = "connections/1.0"

# Message types
CONNECTION_INVITATION = f"{ARIES_PROTOCOL}/invitation"
CONNECTION_REQUEST = f"{ARIES_PROTOCOL}/request"
CONNECTION_RESPONSE = f"{ARIES_PROTOCOL}/response"
PROBLEM_REPORT = f"{ARIES_PROTOCOL}/problem_report"

PROTOCOL_PACKAGE = "acapy_agent.protocols.connections.v1_0"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        CONNECTION_INVITATION: (
            f"{PROTOCOL_PACKAGE}.messages.connection_invitation.ConnectionInvitation"
        ),
        CONNECTION_REQUEST: (
            f"{PROTOCOL_PACKAGE}.messages.connection_request.ConnectionRequest"
        ),
        CONNECTION_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.connection_response.ConnectionResponse"
        ),
        PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.ConnectionProblemReport"
        ),
    }
)
