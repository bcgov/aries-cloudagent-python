"""Class to manage transactions."""

import logging
import uuid
from asyncio import shield
import json
from time import time

from .models.transaction_record import TransactionRecord
from .messages.transaction_request import TransactionRequest
from .messages.endorsed_transaction_response import EndorsedTransactionResponse
from .messages.refused_transaction_response import RefusedTransactionResponse
from .messages.cancel_transaction import CancelTransaction
from .messages.transaction_resend import TransactionResend
from .messages.transaction_job_to_send import TransactionJobToSend
from .messages.transaction_acknowledgement import TransactionAcknowledgement

from ....connections.models.conn_record import ConnRecord
from ....transport.inbound.receipt import MessageReceipt
from ....storage.error import StorageNotFoundError

from ....core.error import BaseError
from ....core.profile import ProfileSession

from ....ledger.base import BaseLedger

from ....indy.issuer import IndyIssuerError
from ....ledger.error import LedgerError

from ....storage.base import StorageRecord
from ....messaging.schemas.util import SCHEMA_SENT_RECORD_TYPE
from ....messaging.credential_definitions.util import CRED_DEF_SENT_RECORD_TYPE
from .transaction_jobs import TransactionJob


class TransactionManagerError(BaseError):
    """Transaction error."""


class TransactionManager:
    """Class for managing transactions."""

    def __init__(self, session: ProfileSession):
        """
        Initialize a TransactionManager.

        Args:
            session: The Profile Session for this transaction manager
        """
        self._session = session
        self._logger = logging.getLogger(__name__)

    @property
    def session(self) -> ProfileSession:
        """
        Accessor for the current Profile Session.

        Returns:
            The Profile Session for this transaction manager

        """
        return self._session

    async def create_record(self, messages_attach: str, connection_id: str):
        """
        Create a new Transaction Record.

        Args:
            connection_id: The connection_id of the ConnRecord between author and endorser
            transaction_message: The actual data in the transaction payload

        Returns:
            The transaction Record

        """

        messages_attach_dict = {
            "@id": str(uuid.uuid4()),
            "mime-type": "application/json",
            "data": {"json": messages_attach},
        }

        transaction = TransactionRecord()

        formats = {
            "attach_id": messages_attach_dict["@id"],
            "format": TransactionRecord.FORMAT_VERSION,
        }
        transaction.formats.clear()
        transaction.formats.append(formats)

        transaction.messages_attach.clear()
        transaction.messages_attach.append(messages_attach_dict)
        transaction.state = TransactionRecord.STATE_TRANSACTION_CREATED
        transaction.connection_id = connection_id

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Created a Transaction Record")

        return transaction

    # todo - implementing changes for writing final transaction to the ledger
    # (For Sign Transaction Protocol)
    async def create_request(
        self,
        transaction: TransactionRecord,
        signature: str = None,
        signed_request: dict = None,
        expires_time: str = None,
    ):
        """
        Create a new Transaction Request.

        Args:
            transaction: The transaction from which the request is created.
            expires_time: The time till which the endorser should endorse the transaction.

        Returns:
            The transaction Record and transaction request

        """

        if transaction.state != TransactionRecord.STATE_TRANSACTION_CREATED:
            raise TransactionManagerError(
                f"Cannot create a request for transaction record"
                f" in state: {transaction.state}"
            )

        transaction._type = TransactionRecord.SIGNATURE_REQUEST
        signature_request = {
            "context": TransactionRecord.SIGNATURE_CONTEXT,
            "method": TransactionRecord.ADD_SIGNATURE,
            "signature_type": TransactionRecord.SIGNATURE_TYPE,
            "signer_goal_code": TransactionRecord.ENDORSE_TRANSACTION,
            "author_goal_code": TransactionRecord.WRITE_TRANSACTION,
        }
        transaction.signature_request.clear()
        transaction.signature_request.append(signature_request)

        transaction.state = TransactionRecord.STATE_REQUEST_SENT

        timing = {"expires_time": expires_time}
        transaction.timing = timing

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Created an endorsement request")

        transaction_request = TransactionRequest(
            transaction_id=transaction._id,
            signature_request=transaction.signature_request[0],
            timing=transaction.timing,
            messages_attach=transaction.messages_attach[0],
        )

        return transaction, transaction_request

    async def receive_request(self, request: TransactionRequest, connection_id: str):
        """
        Receive a Transaction request.

        Args:
            request: A Transaction Request
            connection_id: The connection id related to this transaction record
        """

        transaction = TransactionRecord()

        transaction._type = TransactionRecord.SIGNATURE_REQUEST
        transaction.signature_request.clear()
        transaction.signature_request.append(request.signature_request)
        transaction.timing = request.timing

        format = {
            "attach_id": request.messages_attach["@id"],
            "format": TransactionRecord.FORMAT_VERSION,
        }
        transaction.formats.clear()
        transaction.formats.append(format)

        transaction.messages_attach.clear()
        transaction.messages_attach.append(request.messages_attach)
        transaction.thread_id = request.transaction_id
        transaction.connection_id = connection_id
        transaction.state = TransactionRecord.STATE_REQUEST_RECEIVED

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Received an endorsement request")

        return transaction

    # todo - implementing changes for writing final transaction to the ledger
    # (For Sign Transaction Protocol)
    async def create_endorse_response(
        self,
        transaction: TransactionRecord,
        state: str,
        endorser_did: str,
        endorser_verkey: str,
        endorsed_msg: str = None,
        signature: str = None,
    ):
        """
        Create a response to endorse a transaction.

        Args:
            transaction: The transaction record which would be endorsed.
            state: The state of the transaction record

        Returns:
            The updated transaction and an endorsed response

        """

        if transaction.state not in (
            TransactionRecord.STATE_REQUEST_RECEIVED,
            TransactionRecord.STATE_TRANSACTION_RESENT_RECEIEVED,
        ):
            raise TransactionManagerError(
                f"Cannot endorse transaction for transaction record"
                f" in state: {transaction.state}"
            )

        transaction._type = TransactionRecord.SIGNATURE_RESPONSE

        # don't modify the transaction payload?
        if endorsed_msg:
            # need to return the endorsed msg or else the ledger will reject the
            # eventual transaction write
            transaction.messages_attach[0]["data"]["json"] = endorsed_msg

        signature_response = {
            "message_id": transaction.messages_attach[0]["@id"],
            "context": TransactionRecord.SIGNATURE_CONTEXT,
            "method": TransactionRecord.ADD_SIGNATURE,
            "signer_goal_code": TransactionRecord.ENDORSE_TRANSACTION,
            "signature_type": TransactionRecord.SIGNATURE_TYPE,
            "signature": {endorser_did: signature or endorser_verkey},
        }

        transaction.signature_response.clear()
        transaction.signature_response.append(signature_response)

        transaction.state = state

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Created an endorsed response")

        endorsed_transaction_response = EndorsedTransactionResponse(
            transaction_id=transaction.thread_id,
            thread_id=transaction._id,
            signature_response=signature_response,
            state=state,
            endorser_did=endorser_did,
        )

        return transaction, endorsed_transaction_response

    async def receive_endorse_response(self, response: EndorsedTransactionResponse):
        """
        Update the transaction record with the endorsed response.

        Args:
            response: The Endorsed Transaction Response
        """

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            transaction = await TransactionRecord.retrieve_by_id(
                session, response.transaction_id
            )

        transaction._type = TransactionRecord.SIGNATURE_RESPONSE
        transaction.state = response.state

        transaction.signature_response.clear()
        transaction.signature_response.append(response.signature_response)

        transaction.thread_id = response.thread_id

        # the returned signature is actually the endorsed ledger transaction
        endorser_did = response.endorser_did
        transaction.messages_attach[0]["data"]["json"] = response.signature_response[
            "signature"
        ][endorser_did]

        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Received an endorsed response")

        return transaction

    async def complete_transaction(self, transaction: TransactionRecord):
        """
        Complete a transaction.

        This is the final state where the received ledger transaction
        is written to the ledger.

        Args:
            transaction: The transaction record which would be completed

        Returns:
            The updated transaction

        """

        profile_session = await self.session
        transaction.state = TransactionRecord.STATE_TRANSACTION_ACKED

        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Completed transaction")

        connection_id = transaction.connection_id

        async with profile_session.profile.session() as session:
            connection_record = await ConnRecord.retrieve_by_id(session, connection_id)
        jobs = await connection_record.metadata_get(self._session, "transaction_jobs")
        if not jobs:
            raise TransactionManagerError(
                "The transaction related jobs are not set up in "
                "connection metadata for this connection record"
            )
        if "transaction_my_job" not in jobs.keys():
            raise TransactionManagerError(
                'The "transaction_my_job" is not set in "transaction_jobs"'
                " in connection metadata for this connection record"
            )
        if jobs["transaction_my_job"] == TransactionJob.TRANSACTION_AUTHOR.name:
            await self.store_record_in_wallet(transaction)

        transaction_acknowledgement_message = TransactionAcknowledgement(
            thread_id=transaction._id
        )

        return transaction, transaction_acknowledgement_message

    async def receive_transaction_acknowledgement(
        self, response: TransactionAcknowledgement, connection_id: str
    ):
        """
        Update the transaction record after receiving the transaction acknowledgement.

        Args:
            response: The transaction acknowledgement
            connection_id: The connection_id related to this Transaction Record
        """

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            transaction = await TransactionRecord.retrieve_by_connection_and_thread(
                session, connection_id, response.thread_id
            )

        if transaction.state != TransactionRecord.STATE_TRANSACTION_ENDORSED:
            raise TransactionManagerError(
                "Only an endorsed transaction can be written to the ledger."
            )

        transaction.state = TransactionRecord.STATE_TRANSACTION_ACKED
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Received a transaction ack")

        connection_id = transaction.connection_id

        try:
            async with profile_session.profile.session() as session:
                connection_record = await ConnRecord.retrieve_by_id(
                    session, connection_id
                )
        except StorageNotFoundError as err:
            raise TransactionManagerError(err.roll_up) from err
        jobs = await connection_record.metadata_get(self._session, "transaction_jobs")
        if not jobs:
            raise TransactionManagerError(
                "The transaction related jobs are not set up in "
                "connection metadata for this connection record"
            )
        if "transaction_my_job" not in jobs.keys():
            raise TransactionManagerError(
                'The "transaction_my_job" is not set in "transaction_jobs"'
                " in connection metadata for this connection record"
            )
        if jobs["transaction_my_job"] == TransactionJob.TRANSACTION_AUTHOR.name:
            await self.store_record_in_wallet(transaction)

        return transaction

    async def create_refuse_response(
        self, transaction: TransactionRecord, state: str, refuser_did: str
    ):
        """
        Create a response to refuse a transaction.

        Args:
            transaction: The transaction record which would be refused
            state: The state of the transaction record

        Returns:
            The updated transaction and the refused response

        """

        if transaction.state not in (
            TransactionRecord.STATE_REQUEST_RECEIVED,
            TransactionRecord.STATE_TRANSACTION_RESENT_RECEIEVED,
        ):
            raise TransactionManagerError(
                f"Cannot refuse transaction for transaction record"
                f" in state: {transaction.state}"
            )

        transaction._type = TransactionRecord.SIGNATURE_RESPONSE

        signature_response = {
            "message_id": transaction.messages_attach[0]["@id"],
            "context": TransactionRecord.SIGNATURE_CONTEXT,
            "method": TransactionRecord.ADD_SIGNATURE,
            "signer_goal_code": TransactionRecord.REFUSE_TRANSACTION,
        }
        transaction.signature_response.clear()
        transaction.signature_response.append(signature_response)

        transaction.state = state

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Created a refused response")

        refused_transaction_response = RefusedTransactionResponse(
            transaction_id=transaction.thread_id,
            thread_id=transaction._id,
            signature_response=signature_response,
            state=state,
            endorser_did=refuser_did,
        )

        return transaction, refused_transaction_response

    async def receive_refuse_response(self, response: RefusedTransactionResponse):
        """
        Update the transaction record with a refused response.

        Args:
            response: The refused transaction response
        """

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            transaction = await TransactionRecord.retrieve_by_id(
                session, response.transaction_id
            )

        transaction._type = TransactionRecord.SIGNATURE_RESPONSE
        transaction.state = response.state

        transaction.signature_response.clear()
        transaction.signature_response.append(response.signature_response)
        transaction.thread_id = response.thread_id

        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Received a refused response")

        return transaction

    async def cancel_transaction(self, transaction: TransactionRecord, state: str):
        """
        Cancel a Transaction Request.

        Args:
            transaction: The transaction record which would be cancelled
            state: The state of the transaction record

        Returns:
            The updated transaction and the cancelled transaction response

        """

        if transaction.state not in (
            TransactionRecord.STATE_REQUEST_SENT,
            TransactionRecord.STATE_TRANSACTION_RESENT,
        ):
            raise TransactionManagerError(
                f"Cannot cancel transaction as transaction is"
                f" in state: {transaction.state}"
            )

        transaction.state = state
        profile_session = await self.session
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Cancelled the transaction")

        cancelled_transaction_response = CancelTransaction(
            state=state, thread_id=transaction._id
        )

        return transaction, cancelled_transaction_response

    async def receive_cancel_transaction(
        self, response: CancelTransaction, connection_id: str
    ):
        """
        Update the transaction record to cancel a transaction request.

        Args:
            response: The cancel transaction response
            connection_id: The connection_id related to this Transaction Record
        """

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            transaction = await TransactionRecord.retrieve_by_connection_and_thread(
                session, connection_id, response.thread_id
            )

        transaction.state = response.state
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Received a cancel request")

        return transaction

    async def transaction_resend(self, transaction: TransactionRecord, state: str):
        """
        Resend a transaction request.

        Args:
            transaction: The transaction record which needs to be resend
            state: the state of the transaction record

        Returns:
            The updated transaction and the resend response

        """

        if transaction.state not in (
            TransactionRecord.STATE_TRANSACTION_REFUSED,
            TransactionRecord.STATE_TRANSACTION_CANCELLED,
        ):
            raise TransactionManagerError(
                f"Cannot resend transaction as transaction is"
                f" in state: {transaction.state}"
            )

        transaction.state = state
        profile_session = await self.session
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Resends the transaction request")

        resend_transaction_response = TransactionResend(
            state=TransactionRecord.STATE_TRANSACTION_RESENT_RECEIEVED,
            thread_id=transaction._id,
        )

        return transaction, resend_transaction_response

    async def receive_transaction_resend(
        self, response: TransactionResend, connection_id: str
    ):
        """
        Update the transaction with a resend request.

        Args:
            response: The Resend transaction response
            connection_id: The connection_id related to this Transaction Record
        """

        profile_session = await self.session
        async with profile_session.profile.session() as session:
            transaction = await TransactionRecord.retrieve_by_connection_and_thread(
                session, connection_id, response.thread_id
            )

        transaction.state = response.state
        async with profile_session.profile.session() as session:
            await transaction.save(session, reason="Receives a transaction request")

        return transaction

    async def set_transaction_my_job(self, record: ConnRecord, transaction_my_job: str):
        """
        Set transaction_my_job.

        Args:
            record: The connection record in which to set transaction jobs
            transaction_my_job: My transaction job

        Returns:
            The transaction job that is send to other agent

        """

        value = await record.metadata_get(self._session, "transaction_jobs")

        if value:
            value["transaction_my_job"] = transaction_my_job
        else:
            value = {"transaction_my_job": transaction_my_job}
        await record.metadata_set(self._session, key="transaction_jobs", value=value)

        tx_job_to_send = TransactionJobToSend(job=transaction_my_job)
        return tx_job_to_send

    async def set_transaction_their_job(
        self, tx_job_received: TransactionJobToSend, receipt: MessageReceipt
    ):
        """
        Set transaction_their_job.

        Args:
            tx_job_received: The transaction job that is received from the other agent
            receipt: The Message Receipt Object
        """

        try:
            connection = await ConnRecord.retrieve_by_did(
                self._session, receipt.sender_did, receipt.recipient_did
            )
        except StorageNotFoundError as err:
            raise TransactionManagerError(err.roll_up) from err

        value = await connection.metadata_get(self._session, "transaction_jobs")
        if value:
            value["transaction_their_job"] = tx_job_received.job
        else:
            value = {"transaction_their_job": tx_job_received.job}
        await connection.metadata_set(
            self._session, key="transaction_jobs", value=value
        )

    async def store_record_in_wallet(self, transaction: TransactionRecord):
        """
        Store record in wallet.

        Args:
            transaction: The transaction from which the schema/cred_def
                         would be stored in wallet.
        """

        ledger_transaction = transaction.messages_attach[0]["data"]["json"]

        ledger = self._session.inject(BaseLedger)
        if not ledger:
            reason = "No ledger available"
            if not self._session.context.settings.get_value("wallet.type"):
                reason += ": missing wallet-type?"
            raise TransactionManagerError(reason)

        async with ledger:
            try:
                ledger_response_json = await shield(
                    ledger.txn_submit(ledger_transaction, sign=False, taa_accept=False)
                )
            except (IndyIssuerError, LedgerError) as err:
                raise TransactionManagerError(err.roll_up) from err

        ledger_response = json.loads(ledger_response_json)

        # write the wallet non-secrets record
        # TODO refactor this code (duplicated from ledger.indy.py)
        if ledger_response["result"]["txn"]["type"] == "101":
            # schema transaction
            schema_id = ledger_response["result"]["txnMetadata"]["txnId"]
            schema_id_parts = schema_id.split(":")
            public_did = ledger_response["result"]["txn"]["metadata"]["from"]
            schema_tags = {
                "schema_id": schema_id,
                "schema_issuer_did": public_did,
                "schema_name": schema_id_parts[-2],
                "schema_version": schema_id_parts[-1],
                "epoch": str(int(time())),
            }
            record = StorageRecord(SCHEMA_SENT_RECORD_TYPE, schema_id, schema_tags)
            # TODO refactor this code?
            async with ledger:
                storage = ledger.get_indy_storage()
                await storage.add_record(record)

        elif ledger_response["result"]["txn"]["type"] == "102":
            # cred def transaction
            async with ledger:
                try:
                    schema_seq_no = str(ledger_response["result"]["txn"]["data"]["ref"])
                    schema_response = await shield(ledger.get_schema(schema_seq_no))
                except (IndyIssuerError, LedgerError) as err:
                    raise TransactionManagerError(err.roll_up) from err

            schema_id = schema_response["id"]
            schema_id_parts = schema_id.split(":")
            public_did = ledger_response["result"]["txn"]["metadata"]["from"]
            credential_definition_id = ledger_response["result"]["txnMetadata"]["txnId"]
            cred_def_tags = {
                "schema_id": schema_id,
                "schema_issuer_did": schema_id_parts[0],
                "schema_name": schema_id_parts[-2],
                "schema_version": schema_id_parts[-1],
                "issuer_did": public_did,
                "cred_def_id": credential_definition_id,
                "epoch": str(int(time())),
            }
            record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE, credential_definition_id, cred_def_tags
            )
            # TODO refactor this code?
            async with ledger:
                storage = ledger.get_indy_storage()
                await storage.add_record(record)

        else:
            # TODO unknown ledger transaction type, just ignore for now ...
            pass
