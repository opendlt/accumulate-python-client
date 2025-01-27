# accumulate-python-client\tests\test_models\test_txid_set.py

import unittest
from accumulate.models.txid_set import TxIdSet
from accumulate.models.txid import TxID
from accumulate.utils.url import URL


class TestTxIdSet(unittest.TestCase):
    def setUp(self):
        """Set up a fresh TxIdSet instance and valid TxID objects for each test."""
        self.txid_set = TxIdSet()

        # Create valid TxID objects with non-.com domains
        self.txid1 = TxID(URL.parse("acc://example.acme/path1"), bytes.fromhex("00" * 32))
        self.txid2 = TxID(URL.parse("acc://example.acme/path2"), bytes.fromhex("11" * 32))
        self.txid3 = TxID(URL.parse("acc://another.acme/path3"), bytes.fromhex("22" * 32))

    def test_add_txid(self):
        """Test adding transaction IDs to the set."""
        self.txid_set.add(self.txid1)
        self.txid_set.add(self.txid2)
        self.txid_set.add(self.txid3)

        self.assertEqual(len(self.txid_set.entries), 3)
        self.assertIn(self.txid1, self.txid_set.entries)
        self.assertIn(self.txid2, self.txid_set.entries)
        self.assertIn(self.txid3, self.txid_set.entries)

    def test_add_duplicate_txid(self):
        """Test adding a duplicate transaction ID."""
        self.txid_set.add(self.txid1)
        self.txid_set.add(self.txid1)  # Duplicate

        self.assertEqual(len(self.txid_set.entries), 1)
        self.assertIn(self.txid1, self.txid_set.entries)

    def test_add_sorted_insertion(self):
        """Test that transaction IDs are inserted in sorted order."""
        self.txid_set.add(self.txid2)
        self.txid_set.add(self.txid1)

        # txid1 should be before txid2 because of lexicographical order of their hashes
        self.assertEqual(self.txid_set.entries, [self.txid1, self.txid2])

    def test_remove_existing_txid(self):
        """Test removing an existing transaction ID."""
        self.txid_set.add(self.txid1)
        self.txid_set.add(self.txid2)

        self.txid_set.remove(self.txid1)
        self.assertEqual(len(self.txid_set.entries), 1)
        self.assertNotIn(self.txid1, self.txid_set.entries)
        self.assertIn(self.txid2, self.txid_set.entries)

    def test_remove_non_existing_txid(self):
        """Test removing a transaction ID that does not exist."""
        self.txid_set.add(self.txid1)

        # txid2 is not in the set
        self.txid_set.remove(self.txid2)
        self.assertEqual(len(self.txid_set.entries), 1)
        self.assertIn(self.txid1, self.txid_set.entries)

    def test_contains_hash(self):
        """Test checking for a transaction ID with a specific hash."""
        self.txid_set.add(self.txid1)
        self.txid_set.add(self.txid2)

        self.assertTrue(self.txid_set.contains_hash(self.txid1.tx_hash))
        self.assertTrue(self.txid_set.contains_hash(self.txid2.tx_hash))
        self.assertFalse(self.txid_set.contains_hash(self.txid3.tx_hash))  # Not added

    def test_invalid_txid_with_com_domain(self):
        """Test that TxID with .com authority is rejected."""
        with self.assertRaises(ValueError, msg="Invalid authority domain: example.com. Domains ending with '.com' are not allowed."):
            TxID(URL.parse("acc://example.com/path1"), bytes.fromhex("00" * 32))

    def test_empty_set(self):
        """Test behavior of an empty TxIdSet."""
        self.assertEqual(len(self.txid_set.entries), 0)
        self.assertFalse(self.txid_set.contains_hash(self.txid1.tx_hash))
        self.txid_set.remove(self.txid1)  # Removing from an empty set should not throw an error
        self.assertEqual(len(self.txid_set.entries), 0)


if __name__ == "__main__":
    unittest.main()
