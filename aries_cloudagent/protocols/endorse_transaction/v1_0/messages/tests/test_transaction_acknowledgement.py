from unittest import mock, TestCase

from asynctest import TestCase as AsyncTestCase

from .....didcomm_prefix import DIDCommPrefix

from ...message_types import TRANSACTION_ACKNOWLEDGEMENT

from ..transaction_acknowledgement import TransactionAcknowledgement


class TestConfig:
    test_thread_id = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


class TestTransactionAcknowledgement(TestCase, TestConfig):
    def setUp(self):
        self.transaction_acknowledgement = TransactionAcknowledgement(
            thread_id=self.test_thread_id
        )

    def test_init(self):
        """Test initialization."""
        assert self.transaction_acknowledgement.thread_id == self.test_thread_id

    def test_type(self):
        """Test type."""
        assert self.transaction_acknowledgement._type == DIDCommPrefix.qualify_current(
            TRANSACTION_ACKNOWLEDGEMENT
        )

    @mock.patch(
        "aries_cloudagent.protocols.endorse_transaction.v1_0.messages."
        "transaction_acknowledgement.TransactionAcknowledgementSchema.load"
    )
    def test_deserialize(self, mock_transaction_acknowledgement_schema_load):
        """
        Test deserialization.
        """
        obj = self.transaction_acknowledgement

        transaction_acknowledgement = TransactionAcknowledgement.deserialize(obj)
        mock_transaction_acknowledgement_schema_load.assert_called_once_with(obj)

        assert (
            transaction_acknowledgement
            is mock_transaction_acknowledgement_schema_load.return_value
        )

    @mock.patch(
        "aries_cloudagent.protocols.endorse_transaction.v1_0.messages."
        "transaction_acknowledgement.TransactionAcknowledgementSchema.dump"
    )
    def test_serialize(self, mock_transaction_acknowledgement_schema_dump):
        """
        Test serialization.
        """
        transaction_acknowledgement_dict = self.transaction_acknowledgement.serialize()
        mock_transaction_acknowledgement_schema_dump.assert_called_once_with(
            self.transaction_acknowledgement
        )

        assert (
            transaction_acknowledgement_dict
            is mock_transaction_acknowledgement_schema_dump.return_value
        )


class TestTransactionAcknowledgementSchema(AsyncTestCase, TestConfig):
    """Test transaction acknowledgement schema."""

    async def test_make_model(self):
        transaction_acknowledgement = TransactionAcknowledgement(
            thread_id=self.test_thread_id
        )
        data = transaction_acknowledgement.serialize()
        model_instance = TransactionAcknowledgement.deserialize(data)
        assert type(model_instance) is type(transaction_acknowledgement)
