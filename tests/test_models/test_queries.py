# accumulate-python-client\tests\test_models\test_queries.py

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
from accumulate.models.signature_types import SignatureType
from accumulate.models.records import AccountRecord, ChainRecord, MessageRecord, RecordRange, UrlRecord, TxIDRecord, SignatureSetRecord, KeyRecord, ChainEntryRecord
from accumulate.models.queries import BlockQuery  # for clarity
from accumulate.utils.address_parse import parse_mh_address
from accumulate.models.queries import AccumulateError

# For CreditRecipient tests used in query-related scenarios:
from accumulate.models.general import CreditRecipient
from accumulate.utils.url import URL, WrongSchemeError

class TestQueries(unittest.TestCase):

    def test_query_base_class(self):
        """Test the base Query class functionality."""
        query = Query(QueryType.DEFAULT, {"param1": "value1"})
        self.assertTrue(query.is_valid())
        self.assertEqual(query.to_dict(), {"queryType": "default", "param1": "value1"})

    def test_default_query(self):
        """Test DefaultQuery functionality."""
        receipt_options = ReceiptOptions(for_any=True)
        query = DefaultQuery(include_receipt=receipt_options)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "default",
            "include_receipt": receipt_options.to_dict(),
        })

    def test_chain_query(self):
        """Test ChainQuery functionality."""
        range_options = RangeOptions(start=1, count=10)
        receipt_options = ReceiptOptions(for_height=100)

        # Error when range is provided along with index/entry.
        query = ChainQuery(
            name="test_chain",
            index=5,
            entry=b"entry_data",
            range=range_options,
            include_receipt=receipt_options,
        )
        with self.assertRaises(AccumulateError):
            query.is_valid()

        query = ChainQuery(name="test_chain", index=5)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "chain",
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
            "queryType": "data",
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
            "queryType": "directory",
            "range": {
                "start": 1,
                "count": 20,
                "from_end": False,
                "expand": False,
            },
        })

    def test_pending_query(self):
        """Test PendingQuery functionality."""
        range_options = RangeOptions(start=0, count=15)
        query = PendingQuery(range=range_options)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "pending",
            "range": {
                "start": 0,
                "count": 15,
                "from_end": False,
                "expand": False,
            },
        })

    def test_block_query(self):
        """Test BlockQuery functionality."""
        # Test with minor and major provided.
        query = BlockQuery(minor=5, major=10)
        query.is_valid()
        # Updated expected dict: only keys that are set are included.
        self.assertEqual(query.to_dict(), {
            "queryType": "block",
            "minor": 5,
            "major": 10,
        })

    def test_anchor_search_query(self):
        """Test AnchorSearchQuery functionality."""
        receipt_options = ReceiptOptions(for_any=True)
        query = AnchorSearchQuery(anchor=b"anchor_data", include_receipt=receipt_options)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "anchor",
            "anchor": "616e63686f725f64617461",  # hex representation of b"anchor_data"
            "include_receipt": receipt_options.to_dict(),
        })

    def test_public_key_search_query(self):
        """Test PublicKeySearchQuery functionality."""
        # Provide a valid hex string as the public key.
        query = PublicKeySearchQuery(public_key="7075626c69635f6b65795f64617461", signature_type=SignatureType.ED25519)
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "publicKeySearch",
            "publicKey": "7075626c69635f6b65795f64617461",
            "Type": SignatureType.ED25519.to_rpc_format(),
        })

    def test_public_key_hash_search_query(self):
        """Test PublicKeyHashSearchQuery functionality."""
        query = PublicKeyHashSearchQuery(public_key_hash="7075626c69635f6b65795f68617368")
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "publicKeyHashSearch",
            "publicKeyHash": "7075626c69635f6b65795f68617368",
        })

    def test_delegate_search_query(self):
        """Test DelegateSearchQuery functionality."""
        query = DelegateSearchQuery(delegate="delegate_address")
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "delegateSearch",
            "delegate": "delegate_address",
        })

    def test_message_hash_search_query(self):
        """Test MessageHashSearchQuery functionality."""
        query = MessageHashSearchQuery(hash=b"message_hash")
        query.is_valid()
        self.assertEqual(query.to_dict(), {
            "queryType": "messageHashSearch",
            "hash": "6d6573736167655f68617368",  # hex representation of b"message_hash"
        })

    def test_query_invalid_query_type(self):
        """Test Query with an invalid query type (None)."""
        query = Query(None)
        self.assertFalse(query.is_valid())

    def test_default_query_invalid_receipt_options(self):
        """Test DefaultQuery with invalid ReceiptOptions."""
        receipt_options = ReceiptOptions(for_any=False, for_height=None)
        query = DefaultQuery(include_receipt=receipt_options)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_chain_query_missing_name(self):
        """Test ChainQuery with missing name while using index, entry, or range."""
        query = ChainQuery(index=1)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_chain_query_invalid_receipt_options(self):
        """Test ChainQuery with invalid ReceiptOptions."""
        receipt_options = ReceiptOptions(for_any=False, for_height=None)
        query = ChainQuery(name="test_chain", include_receipt=receipt_options)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_directory_query_invalid_range(self):
        """Test DirectoryQuery with an invalid RangeOptions."""
        range_options = RangeOptions(start=None, count=None)
        query = DirectoryQuery(range=range_options)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_pending_query_invalid_range(self):
        """Test PendingQuery with an invalid RangeOptions."""
        range_options = RangeOptions(start=None, count=None)
        query = PendingQuery(range=range_options)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_block_query_mutually_exclusive_minor_and_ranges(self):
        """Test BlockQuery where minor is mutually exclusive with minor_range."""
        minor_range = RangeOptions(start=0, count=5)
        query = BlockQuery(minor=5, minor_range=minor_range)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_block_query_invalid_entry_range(self):
        """Test BlockQuery with an invalid entry range."""
        entry_range = RangeOptions(start=None, count=None)
        query = BlockQuery(entry_range=entry_range)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_anchor_search_query_invalid_receipt_options(self):
        """Test AnchorSearchQuery with invalid ReceiptOptions."""
        receipt_options = ReceiptOptions(for_any=False, for_height=None)
        query = AnchorSearchQuery(anchor=b"valid_anchor", include_receipt=receipt_options)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_public_key_search_query_missing_public_key(self):
        """Test PublicKeySearchQuery without a public key."""
        query = PublicKeySearchQuery(public_key="", signature_type=SignatureType.ED25519)
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_public_key_hash_search_query_missing_hash(self):
        """Test PublicKeyHashSearchQuery without a public key hash."""
        query = PublicKeyHashSearchQuery(public_key_hash="")
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_delegate_search_query_missing_delegate(self):
        """Test DelegateSearchQuery without a delegate."""
        query = DelegateSearchQuery(delegate="")
        with self.assertRaises(AccumulateError):
            query.is_valid()

    def test_message_hash_search_query_missing_hash(self):
        """Test MessageHashSearchQuery without a hash."""
        query = MessageHashSearchQuery(hash=b"")
        with self.assertRaises(AccumulateError):
            query.is_valid()

    # --- New tests for CreditRecipient marshalling/unmarshalling as used in queries ---

    def test_marshal_with_non_acc_prefix_url(self):
        """Test that a CreditRecipient built with a URL missing an explicit 'acc://' prefix raises an error."""
        # Create a URL without an explicit "acc://" prefix.
        url = URL(user_info="", authority="test_url_no_prefix", path="")
        recipient = CreditRecipient(url, 100)
        marshaled = recipient.marshal()
        print(f"DEBUG: Marshaled CreditRecipient data: {marshaled.hex()}")
        # Now we expect that unmarshal() will raise WrongSchemeError because the URL string is not normalized.
        with self.assertRaises(WrongSchemeError):
            CreditRecipient.unmarshal(marshaled)

    def test_unmarshal_insufficient_bytes(self):
        """Test that unmarshal() on truncated data raises a WrongSchemeError."""
        url = URL.parse("acc://test_url")
        recipient = CreditRecipient(url, 200)
        marshaled = recipient.marshal()
        # Simulate truncation by removing the last 8 bytes.
        truncated_data = marshaled[:-8]
        print(f"DEBUG: Truncated data: {truncated_data.hex()}")
        # Because the truncated URL string no longer starts with "acc://", we expect WrongSchemeError.
        with self.assertRaises(WrongSchemeError):
            CreditRecipient.unmarshal(truncated_data)

if __name__ == "__main__":
    unittest.main()
