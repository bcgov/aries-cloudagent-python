"""Message type identifiers for Transactions."""

from ...didcomm_prefix import DIDCommPrefix

# Message types

TRANSACTION_REQUEST = "transactions/1.0/request"
ENDORSED_TRANSACTION_RESPONSE = "transactions/1.0/endorse"
REFUSED_TRANSACTION_RESPONSE = "transactions/1.0/refuse"
CANCEL_TRANSACTION = "transactions/1.0/cancel"
TRANSACTION_RESEND = "transactions/1.0/resend"
TRANSACTION_JOB_TO_SEND = "transactions/1.0/transaction_my_job"
TRANSACTION_ACKNOWLEDGEMENT = "transactions/1.0/ack"
ATTACHED_MESSAGE = "transactions/1.0/message"
PROTOCOL_PACKAGE = "aries_cloudagent.protocols.endorse_transaction.v1_0"


MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        TRANSACTION_REQUEST: (
            f"{PROTOCOL_PACKAGE}.messages.transaction_request.TransactionRequest"
        ),
        ENDORSED_TRANSACTION_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.endorsed_transaction_response"
            ".EndorsedTransactionResponse"
        ),
        REFUSED_TRANSACTION_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.refused_transaction_response"
            ".RefusedTransactionResponse"
        ),
        CANCEL_TRANSACTION: (
            f"{PROTOCOL_PACKAGE}.messages.cancel_transaction.CancelTransaction"
        ),
        TRANSACTION_RESEND: (
            f"{PROTOCOL_PACKAGE}.messages.transaction_resend.TransactionResend"
        ),
        TRANSACTION_JOB_TO_SEND: (
            f"{PROTOCOL_PACKAGE}.messages.transaction_job_to_send.TransactionJobToSend"
        ),
        TRANSACTION_ACKNOWLEDGEMENT: (
            f"{PROTOCOL_PACKAGE}.messages.transaction_acknowledgement"
            ".TransactionAcknowledgement"
        ),
    }
)
