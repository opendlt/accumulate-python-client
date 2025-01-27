# accumulate-python-client\tests\test_models\test_submission.py

import unittest
from accumulate.models.submission import Submission


class TestSubmission(unittest.TestCase):
    def test_initialization_default_values(self):
        """Test initializing Submission with default values."""
        submission = Submission()
        self.assertIsNone(submission.txid)
        self.assertIsNone(submission.status)
        self.assertFalse(submission.success)
        self.assertIsNone(submission.message)

    def test_initialization_with_values(self):
        """Test initializing Submission with provided values."""
        txid = "12345"
        status = {"code": 200, "description": "OK"}
        success = True
        message = "Transaction submitted successfully"

        submission = Submission(txid=txid, status=status, success=success, message=message)
        self.assertEqual(submission.txid, txid)
        self.assertEqual(submission.status, status)
        self.assertTrue(submission.success)
        self.assertEqual(submission.message, message)

    def test_to_dict_with_default_values(self):
        """Test to_dict method with default values."""
        submission = Submission()
        expected = {
            "txid": None,
            "status": None,
            "success": False,
            "message": None,
        }
        self.assertEqual(submission.to_dict(), expected)

    def test_to_dict_with_values(self):
        """Test to_dict method with provided values."""
        submission = Submission(
            txid="12345",
            status={"code": 200, "description": "OK"},
            success=True,
            message="Transaction submitted successfully",
        )
        expected = {
            "txid": "12345",
            "status": {"code": 200, "description": "OK"},
            "success": True,
            "message": "Transaction submitted successfully",
        }
        self.assertEqual(submission.to_dict(), expected)

    def test_from_dict_with_default_values(self):
        """Test from_dict method with default values."""
        data = {}
        submission = Submission.from_dict(data)

        self.assertIsNone(submission.txid)
        self.assertIsNone(submission.status)
        self.assertFalse(submission.success)
        self.assertIsNone(submission.message)

    def test_from_dict_with_values(self):
        """Test from_dict method with provided values."""
        data = {
            "txid": "12345",
            "status": {"code": 200, "description": "OK"},
            "success": True,
            "message": "Transaction submitted successfully",
        }
        submission = Submission.from_dict(data)

        self.assertEqual(submission.txid, data["txid"])
        self.assertEqual(submission.status, data["status"])
        self.assertTrue(submission.success)
        self.assertEqual(submission.message, data["message"])

    def test_partial_from_dict(self):
        """Test from_dict with partial data."""
        data = {
            "txid": "12345",
            "success": True,
        }
        submission = Submission.from_dict(data)

        self.assertEqual(submission.txid, data["txid"])
        self.assertIsNone(submission.status)
        self.assertTrue(submission.success)
        self.assertIsNone(submission.message)

    def test_invalid_status_type(self):
        """Test setting an invalid type for the status field."""
        with self.assertRaises(TypeError):
            Submission(status="invalid_status")  # Status should be a dictionary or None



if __name__ == "__main__":
    unittest.main()
