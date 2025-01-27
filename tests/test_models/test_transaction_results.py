# accumulate-python-client\tests\test_models\test_transaction_results.py

import unittest
from accumulate.models.transaction_results import (
    TransactionResult,
    EmptyResult,
    WriteDataResult,
    AddCreditsResult,
    new_transaction_result,
    equal_transaction_result,
    unmarshal_transaction_result,
    copy_transaction_result,
)
from accumulate.utils.url import URL
import json


class TestTransactionResults(unittest.TestCase):

    def test_empty_result(self):
        """Test EmptyResult class functionality."""
        result = EmptyResult()
        copied_result = result.copy()
        self.assertIsInstance(copied_result, EmptyResult)
        self.assertTrue(result.equal(copied_result))
        self.assertFalse(result.equal(WriteDataResult()))

    def test_write_data_result(self):
        """Test WriteDataResult class functionality."""
        entry_hash = b"test_hash"
        account_url = URL(authority="account.acme")
        account_id = b"account_id"
        result = WriteDataResult(entry_hash, account_url, account_id)
        copied_result = result.copy()

        self.assertIsInstance(copied_result, WriteDataResult)
        self.assertEqual(result.entry_hash, copied_result.entry_hash)
        self.assertEqual(result.account_url, copied_result.account_url)
        self.assertEqual(result.account_id, copied_result.account_id)
        self.assertTrue(result.equal(copied_result))

        # Test inequality
        different_result = WriteDataResult(b"other_hash", account_url, account_id)
        self.assertFalse(result.equal(different_result))

    def test_add_credits_result(self):
        """Test AddCreditsResult class functionality."""
        amount, credits, oracle = 100, 50, 10
        result = AddCreditsResult(amount, credits, oracle)
        copied_result = result.copy()

        self.assertIsInstance(copied_result, AddCreditsResult)
        self.assertEqual(result.amount, copied_result.amount)
        self.assertEqual(result.credits, copied_result.credits)
        self.assertEqual(result.oracle, copied_result.oracle)
        self.assertTrue(result.equal(copied_result))

        # Test inequality
        different_result = AddCreditsResult(200, credits, oracle)
        self.assertFalse(result.equal(different_result))

        # Test validation
        with self.assertRaises(ValueError):
            AddCreditsResult(-1, credits, oracle)

    def test_new_transaction_result(self):
        """Test factory method for creating transaction results."""
        result = new_transaction_result("WriteDataResult")
        self.assertIsInstance(result, WriteDataResult)

        result = new_transaction_result("AddCreditsResult")
        self.assertIsInstance(result, AddCreditsResult)

        result = new_transaction_result("EmptyResult")
        self.assertIsInstance(result, EmptyResult)

        with self.assertRaises(ValueError):
            new_transaction_result("UnknownResult")

    def test_equal_transaction_result(self):
        """Test comparing transaction results for equality."""
        result1 = WriteDataResult(b"hash1", URL(authority="test.acme"), b"id1")
        result2 = WriteDataResult(b"hash1", URL(authority="test.acme"), b"id1")
        result3 = AddCreditsResult(100, 50, 10)

        self.assertTrue(equal_transaction_result(result1, result2))
        self.assertFalse(equal_transaction_result(result1, result3))

    def test_unmarshal_transaction_result(self):
        """Test deserializing transaction results."""
        # Test WriteDataResult deserialization
        write_data_json = {
            "Type": "WriteDataResult",
            "entry_hash": b"hash".hex(),  # Hex representation of b"hash"
            "account_url": "acc://test.acme",
            "account_id": b"id".hex(),  # Hex representation of b"id"
        }
        result = unmarshal_transaction_result(json.dumps(write_data_json).encode())
        self.assertIsInstance(result, WriteDataResult)
        self.assertEqual(result.entry_hash, b"hash")  # Ensure it's bytes
        self.assertEqual(result.account_url, URL.parse("acc://test.acme"))
        self.assertEqual(result.account_id, b"id")

        # Test AddCreditsResult deserialization
        add_credits_json = {
            "Type": "AddCreditsResult",
            "amount": 100,
            "credits": 50,
            "oracle": 10,
        }
        result = unmarshal_transaction_result(json.dumps(add_credits_json).encode())
        self.assertIsInstance(result, AddCreditsResult)
        self.assertEqual(result.amount, 100)
        self.assertEqual(result.credits, 50)
        self.assertEqual(result.oracle, 10)

        # Test missing type field
        with self.assertRaises(ValueError) as context:
            unmarshal_transaction_result(json.dumps({}).encode())
        self.assertIn("Missing transaction result type", str(context.exception))

        # Test unknown type
        with self.assertRaises(ValueError) as context:
            unmarshal_transaction_result(json.dumps({"Type": "UnknownResult"}).encode())
        self.assertIn("Unknown transaction result type", str(context.exception))


    def test_copy_transaction_result(self):
        """Test copying transaction results."""
        original_result = WriteDataResult(b"hash", URL(authority="test.acme"), b"id")
        copied_result = copy_transaction_result(original_result)
        self.assertTrue(original_result.equal(copied_result))
        self.assertIsNot(original_result, copied_result)

    def test_deserialize_json(self):
        """Test deserializing JSON into a dictionary."""
        json_data = json.dumps({"key": "value"}).encode()
        deserialized = json.loads(json_data)
        self.assertEqual(deserialized["key"], "value")


if __name__ == "__main__":
    unittest.main()
