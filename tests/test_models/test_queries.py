# C:\Accumulate_Stuff\accumulate-python-client\tests\test_models\test_queries.py

import unittest
from accumulate.models.queries import (
    Query,
    DefaultQuery,
    ChainQuery,
    DataQuery,
    DirectoryQuery,
    PendingQuery,
    BlockQuery,
    AnchorSearchQuery,
    PublicKeySearchQuery,
    PublicKeyHashSearchQuery,
    DelegateSearchQuery,
    MessageHashSearchQuery,
)
from accumulate.models.options import RangeOptions, ReceiptOptions
from accumulate.models.enums import QueryType
from accumulate.api.exceptions import AccumulateError


class TestQueries(unittest.TestCase):

    def test_query_base_class(self):
        """Test the base Query class functionality."""
        query = Query(QueryType.DEFAULT, {"param1": "value1"})
        self.assertTrue(query.is_valid())
        self.assertEqual(query.to_dict(), {"type": "DEFAULT", "params": {"param1": "value1"}})

    def test_default_query(self):
        """Test DefaultQuery functionality."""
        receipt_options = ReceiptOptions(for_any=True)
        query = DefaultQuery(include_receipt=receipt_options)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "DEFAULT",
            "params": {},
            "include_receipt": receipt_options.to_dict(),
        })

    def test_chain_query(self):
        """Test ChainQuery functionality."""
        range_options = RangeOptions(start=1, count=10)
        receipt_options = ReceiptOptions(for_height=100)

        query = ChainQuery(
            name="test_chain",
            index=5,
            entry=b"entry_data",
            range=range_options,
            include_receipt=receipt_options,
        )
        with self.assertRaises(AccumulateError):
            query.is_valid()  # range is mutually exclusive with index/entry

        query = ChainQuery(name="test_chain", index=5)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "CHAIN",
            "params": {},
            "name": "test_chain",
            "index": 5,
            "entry": None,
            "range": None,
            "include_receipt": None,
        })

    def test_data_query(self):
        """Test DataQuery functionality."""
        range_options = RangeOptions(start=0, count=5)

        query = DataQuery(index=3, entry=b"entry_data", range=range_options)
        with self.assertRaises(AccumulateError):
            query.is_valid()  # range is mutually exclusive with index/entry

        query = DataQuery(index=3)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "DATA",
            "params": {},
            "index": 3,
            "entry": None,
            "range": None,
        })

    def test_directory_query(self):
        """Test DirectoryQuery functionality."""
        range_options = RangeOptions(start=1, count=20)
        query = DirectoryQuery(range=range_options)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "DIRECTORY",
            "params": {},
            "range": range_options.to_dict(),
        })

    def test_pending_query(self):
        """Test PendingQuery functionality."""
        range_options = RangeOptions(start=0, count=15)
        query = PendingQuery(range=range_options)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "PENDING",
            "params": {},
            "range": range_options.to_dict(),
        })

    def test_block_query(self):
        """Test BlockQuery functionality."""
        minor_range = RangeOptions(start=1, count=10)
        major_range = RangeOptions(start=20, count=30)

        query = BlockQuery(minor=5, major=10)
        with self.assertRaises(AccumulateError):
            query.is_valid()  # minor and major are mutually exclusive

        query = BlockQuery(minor_range=minor_range, entry_range=major_range)
        with self.assertRaises(AccumulateError):
            query.is_valid()  # entry range is mutually exclusive with minor/major range

        query = BlockQuery(minor=5)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "BLOCK",
            "params": {},
            "minor": 5,
            "major": None,
            "minor_range": None,
            "major_range": None,
            "entry_range": None,
            "omit_empty": None,
        })

    def test_anchor_search_query(self):
        """Test AnchorSearchQuery functionality."""
        receipt_options = ReceiptOptions(for_any=True)
        query = AnchorSearchQuery(anchor=b"anchor_data", include_receipt=receipt_options)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "ANCHOR_SEARCH",
            "params": {},
            "anchor": "616e63686f725f64617461",  # hex representation
            "include_receipt": receipt_options.to_dict(),
        })

    def test_public_key_search_query(self):
        """Test PublicKeySearchQuery functionality."""
        query = PublicKeySearchQuery(public_key=b"public_key_data", signature_type="ecdsa")
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "PUBLIC_KEY_SEARCH",
            "params": {},
            "public_key": "7075626c69635f6b65795f64617461",  # hex representation
            "signature_type": "ecdsa",
        })

    def test_public_key_hash_search_query(self):
        """Test PublicKeyHashSearchQuery functionality."""
        query = PublicKeyHashSearchQuery(public_key_hash=b"public_key_hash")
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "PUBLIC_KEY_HASH_SEARCH",
            "params": {},
            "public_key_hash": "7075626c69635f6b65795f68617368",  # hex representation
        })

    def test_delegate_search_query(self):
        """Test DelegateSearchQuery functionality."""
        query = DelegateSearchQuery(delegate="delegate_address")
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "DELEGATE_SEARCH",
            "params": {},
            "delegate": "delegate_address",
        })

    def test_message_hash_search_query(self):
        """Test MessageHashSearchQuery functionality."""
        query = MessageHashSearchQuery(hash=b"message_hash")
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "type": "MESSAGE_HASH_SEARCH",
            "params": {},
            "hash": "6d6573736167655f68617368",  # hex representation
        })


if __name__ == "__main__":
    unittest.main()
