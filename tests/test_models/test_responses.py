# accumulate-python-client\tests\test_models\test_responses.py

import unittest
from unittest.mock import MagicMock, patch
from accumulate.models.responses import SubmissionResponse, TransactionResultSet
from accumulate.models.protocol import Receipt
from accumulate.models.transactions import TransactionStatus
import logging
import re

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TestSubmissionResponse(unittest.TestCase):
    def setUp(self):
        # Patch TransactionStatus where it is used in the responses module.
        self.patcher_status = patch('accumulate.models.responses.TransactionStatus')
        self.MockTransactionStatus = self.patcher_status.start()
        self.addCleanup(self.patcher_status.stop)

        # Patch Receipt from the protocol module.
        self.patcher_receipt = patch('accumulate.models.protocol.Receipt')
        self.MockReceipt = self.patcher_receipt.start()
        self.addCleanup(self.patcher_receipt.stop)

        # Define a fake from_dict for TransactionStatus that returns a mock with to_dict() returning the input data.
        def fake_ts_from_dict(data):
            mock_ts = MagicMock()
            mock_ts.to_dict.return_value = data
            return mock_ts
        self.MockTransactionStatus.from_dict.side_effect = fake_ts_from_dict

        # Define a fake from_dict for Receipt that creates a Receipt instance using the provided data.
        self.MockReceipt.from_dict.side_effect = lambda data: Receipt(**data)



    def test_submission_response_default_initialization(self):
        """Test initializing SubmissionResponse with default values."""
        response = SubmissionResponse()
        self.assertIsNone(response.status)
        self.assertFalse(response.success)
        self.assertIsNone(response.message)
        self.assertIsNone(response.receipt)

    def test_submission_response_with_values(self):
        """Test initializing SubmissionResponse with provided values."""
        mock_status = MagicMock(to_dict=lambda: {"mock_key": "mock_value"})
        mock_receipt = Receipt(local_block=123, local_block_time="2023-01-01T12:00:00Z", major_block=456)

        response = SubmissionResponse(
            status=mock_status,
            success=True,
            message="Submission successful",
            receipt=mock_receipt,
        )
        self.assertEqual(response.status, mock_status)
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Submission successful")
        self.assertEqual(response.receipt, mock_receipt)

    def test_submission_response_to_dict_with_defaults(self):
        """Test the to_dict method with default values."""
        response = SubmissionResponse()
        expected = {
            "status": None,
            "success": False,
            "message": None,
            "receipt": None,
        }
        self.assertEqual(response.to_dict(), expected)

    def test_submission_response_from_dict_with_values(self):
        """Test deserialization with values."""
        data = {
            "status": {"mock_key": "mock_value"},
            "success": True,
            "message": "Submission successful",
            "receipt": {
                "local_block": 123,
                "local_block_time": "2023-01-01T12:00:00Z",
                "major_block": 456,
            },
        }

        response = SubmissionResponse.from_dict(data)
        print(f"[DEBUG] SubmissionResponse.to_dict(): {response.to_dict()}")

        # Assertions
        self.assertEqual(response.status.to_dict(), {"mock_key": "mock_value"})
        self.assertTrue(response.success)
        self.assertEqual(response.message, "Submission successful")
        self.assertEqual(
            response.receipt.to_dict(),
            {
                "local_block": 123,
                "local_block_time": "2023-01-01T12:00:00Z",
                "major_block": 456,
            },
        )

    def test_submission_response_from_dict_with_defaults(self):
        """Test the from_dict method with default values."""
        data = {}
        response = SubmissionResponse.from_dict(data)
        self.assertIsNone(response.status)
        self.assertFalse(response.success)
        self.assertIsNone(response.message)
        self.assertIsNone(response.receipt)


class TestTransactionResultSet(unittest.TestCase):
    def setUp(self):
        # Patch TransactionStatus where it is used in the responses module.
        self.patcher_status = patch('accumulate.models.responses.TransactionStatus')
        self.MockTransactionStatus = self.patcher_status.start()
        self.addCleanup(self.patcher_status.stop)

        # Use a custom fake from_dict that creates a TransactionStatus instance without the 'signers' keyword,
        # then assigns the signers attribute afterward.
        def fake_ts_from_dict(data):
            ts = TransactionStatus(
                tx_id=data.get("tx_id"),
                code=data.get("code", 0),
                error=data.get("error"),
                result=data.get("result"),
                received=data.get("received"),
                initiator=data.get("initiator")
            )
            ts.signers = data.get("signers", [])
            return ts
        self.MockTransactionStatus.from_dict.side_effect = fake_ts_from_dict


    def test_transaction_result_set_default_initialization(self):
        """Test initializing TransactionResultSet with default values."""
        result_set = TransactionResultSet()
        self.assertEqual(result_set.results, [])

    def test_transaction_result_set_with_values(self):
        """Test initializing TransactionResultSet with provided values."""
        mock_status1 = TransactionStatus(tx_id="1", code=0)
        mock_status2 = TransactionStatus(tx_id="2", code=0)
        result_set = TransactionResultSet(results=[mock_status1, mock_status2])
        self.assertEqual(result_set.results, [mock_status1, mock_status2])

    def test_transaction_result_set_add_result(self):
        """Test adding a TransactionStatus to the result set."""
        result_set = TransactionResultSet()
        mock_status1 = TransactionStatus(tx_id="1", code=0)
        mock_status2 = TransactionStatus(tx_id="2", code=0)

        result_set.add_result(mock_status1)
        self.assertEqual(result_set.results, [mock_status1])

        result_set.add_result(mock_status2)
        self.assertEqual(result_set.results, [mock_status1, mock_status2])

    def test_transaction_result_set_to_dict_with_defaults(self):
        """Test the to_dict method with default values."""
        result_set = TransactionResultSet()
        expected = {"results": []}
        self.assertEqual(result_set.to_dict(), expected)

    def test_transaction_result_set_to_dict_with_values(self):
        """Test the to_dict method with provided values."""
        mock_status1 = TransactionStatus(tx_id="1", code=0)
        mock_status2 = TransactionStatus(tx_id="2", code=0)
        result_set = TransactionResultSet(results=[mock_status1, mock_status2])
        expected = {
            "results": [
                {"tx_id": "1", "code": 0, "error": None, "result": None, "received": None, "initiator": None, "signers": []},
                {"tx_id": "2", "code": 0, "error": None, "result": None, "received": None, "initiator": None, "signers": []},
            ]
        }
        self.assertEqual(result_set.to_dict(), expected)

    def test_transaction_result_set_from_dict_with_defaults(self):
        """Test the from_dict method with default values."""
        data = {}
        result_set = TransactionResultSet.from_dict(data)
        self.assertEqual(result_set.results, [])

    def test_transaction_result_set_from_dict_with_values(self):
        """Test deserialization with values."""
        data = {
            "results": [
                {"tx_id": "1", "code": 0},
                {"tx_id": "2", "code": 0},
            ]
        }

        result_set = TransactionResultSet.from_dict(data)
        print(f"[DEBUG] TransactionResultSet.to_dict(): {result_set.to_dict()}")

        self.assertEqual(
            [result.to_dict() for result in result_set.results],
            [
                {"tx_id": "1", "code": 0, "error": None, "result": None, "received": None, "initiator": None, "signers": []},
                {"tx_id": "2", "code": 0, "error": None, "result": None, "received": None, "initiator": None, "signers": []},
            ],
        )


if __name__ == "__main__":
    unittest.main()
