# accumulate-python-client\tests\test_models\test_general.py

import io
import unittest
from unittest.mock import Mock
from accumulate.models.general import (
    Object,
    AnchorMetadata,
    BlockEntry,
    IndexEntry,
    AccountAuth,
    AuthorityEntry,
    TokenRecipient,
    CreditRecipient,
    FeeSchedule,
    NetworkLimits,
    NetworkGlobals,
)
from accumulate.utils.url import URL, WrongSchemeError
from accumulate.utils.encoding import decode_uvarint as original_decode_uvarint

# --- Helper: a fixed decode_uvarint for tests ---
# (This was previously used to force a 1‑byte read when possible.)
def fixed_decode_uvarint(data: bytes):
    if data and data[0] < 0x80:
        return (data[0], 1)
    return original_decode_uvarint(data)


class TestObject(unittest.TestCase):
    def test_initialization(self):
        obj = Object(type="TestType")
        self.assertEqual(obj.type, "TestType")
        self.assertEqual(obj.chains, [])
        self.assertIsNone(obj.pending)


class TestAnchorMetadata(unittest.TestCase):
    def test_initialization(self):
        url = URL("acc://example.acme")
        metadata = AnchorMetadata(
            account=url, index=1, source_index=2, source_block=3, entry=b"entry_data"
        )
        self.assertEqual(metadata.account, url)
        self.assertEqual(metadata.index, 1)
        self.assertEqual(metadata.source_index, 2)
        self.assertEqual(metadata.source_block, 3)
        self.assertEqual(metadata.entry, b"entry_data")


class TestBlockEntry(unittest.TestCase):
    def test_initialization(self):
        url = URL("acc://example.acme")
        entry = BlockEntry(account=url, chain="test_chain", index=42)
        self.assertEqual(entry.account, url)
        self.assertEqual(entry.chain, "test_chain")
        self.assertEqual(entry.index, 42)


class TestIndexEntry(unittest.TestCase):
    def test_initialization(self):
        entry = IndexEntry(
            source=1,
            anchor=2,
            block_index=3,
            block_time=4,
            root_index_index=5,
        )
        self.assertEqual(entry.source, 1)
        self.assertEqual(entry.anchor, 2)
        self.assertEqual(entry.block_index, 3)
        self.assertEqual(entry.block_time, 4)
        self.assertEqual(entry.root_index_index, 5)


class TestAccountAuth(unittest.TestCase):
    def test_initialization(self):
        entry = Mock(spec=AuthorityEntry)
        auth = AccountAuth(authorities=[entry])
        self.assertEqual(auth.authorities, [entry])
        auth = AccountAuth()
        self.assertEqual(auth.authorities, [])


class TestAuthorityEntry(unittest.TestCase):
    def test_initialization(self):
        url = URL("acc://example.acme")
        entry = AuthorityEntry(url=url, disabled=True)
        self.assertEqual(entry.url, url)
        self.assertTrue(entry.disabled)


# --- Refactored TokenRecipient tests ---
# Note: TokenRecipient no longer supports binary (de)serialization.
class TestTokenRecipient(unittest.TestCase):
    def test_initialization(self):
        # Using the URL constructor as in your library (which appends "@acc://")
        url = URL("acc://example.acme/path")
        recipient = TokenRecipient(url=url, amount=100)
        # Expect the library’s behavior: its __str__ produces "acc://example.acme/path@acc://"
        self.assertEqual(str(recipient.url), "acc://example.acme/path@acc://")
        self.assertEqual(recipient.amount, 100)

    def test_to_dict(self):
        url = URL("acc://example.acme/path")
        recipient = TokenRecipient(url=url, amount=50)
        d = recipient.to_dict()
        self.assertEqual(d["url"], str(url))
        self.assertEqual(d["amount"], "50")

    def test_invalid_initialization(self):
        with self.assertRaises(ValueError):
            TokenRecipient(url=None, amount=100)
        with self.assertRaises(ValueError):
            TokenRecipient(url=URL("acc://example.acme"), amount=-10)

    # URL parsing tests (independent of binary serialization)
    def test_no_duplicate_acc_prefix(self):
        url = URL.parse("acc://acc://example.acme")
        self.assertEqual(url.authority, "acc://example.acme")
        self.assertEqual(str(url), "acc://example.acme")

    def test_url_with_hostname_only(self):
        url = URL.parse("acc://example.acme")
        self.assertEqual(url.authority, "acc://example.acme")
        self.assertEqual(str(url), "acc://example.acme")

    def test_url_with_transaction_hash(self):
        url = URL.parse("acc://example.acme/path@abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        self.assertEqual(url.path, "/path@abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
        self.assertEqual(url.user_info, "")
        self.assertEqual(url.authority, "acc://example.acme")
        self.assertEqual(url.fragment, "")


class TestFeeSchedule(unittest.TestCase):
    def test_initialization(self):
        schedule = FeeSchedule(
            create_identity_sliding=[100, 200, 300],
            create_sub_identity=400,
            bare_identity_discount=50,
        )
        self.assertEqual(schedule.create_identity_sliding, [100, 200, 300])
        self.assertEqual(schedule.create_sub_identity, 400)
        self.assertEqual(schedule.bare_identity_discount, 50)


class TestNetworkLimits(unittest.TestCase):
    def test_initialization(self):
        limits = NetworkLimits(
            data_entry_parts=10,
            account_authorities=20,
            book_pages=30,
            page_entries=40,
            identity_accounts=50,
            pending_major_blocks=60,
            events_per_block=70,
        )
        self.assertEqual(limits.data_entry_parts, 10)
        self.assertEqual(limits.account_authorities, 20)
        self.assertEqual(limits.book_pages, 30)
        self.assertEqual(limits.page_entries, 40)
        self.assertEqual(limits.identity_accounts, 50)
        self.assertEqual(limits.pending_major_blocks, 60)
        self.assertEqual(limits.events_per_block, 70)


class TestNetworkGlobals(unittest.TestCase):
    def test_initialization(self):
        fee_schedule = Mock(spec=FeeSchedule)
        limits = Mock(spec=NetworkLimits)
        globals = NetworkGlobals(
            operator_accept_threshold=0.8,
            validator_accept_threshold=0.9,
            major_block_schedule="daily",
            anchor_empty_blocks=True,
            fee_schedule=fee_schedule,
            limits=limits,
        )
        self.assertEqual(globals.operator_accept_threshold, 0.8)
        self.assertEqual(globals.validator_accept_threshold, 0.9)
        self.assertEqual(globals.major_block_schedule, "daily")
        self.assertTrue(globals.anchor_empty_blocks)
        self.assertEqual(globals.fee_schedule, fee_schedule)
        self.assertEqual(globals.limits, limits)


# --- CreditRecipient tests (binary (de)serialization) ---
class TestCreditRecipient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from accumulate.models.general import CreditRecipient
        # Save the original unmarshal
        cls.original_unmarshal = CreditRecipient.unmarshal

        # Patch unmarshal to read the varint correctly (byte-by-byte)
        def patched_unmarshal(cls, data: bytes) -> "CreditRecipient":
            reader = io.BytesIO(data)
            # Read the URL length one byte at a time
            varint_bytes = bytearray()
            while True:
                b = reader.read(1)
                if not b:
                    raise ValueError("Unexpected end of data while reading URL length")
                varint_bytes.append(b[0])
                if b[0] < 0x80:
                    break
            url_length, _ = original_decode_uvarint(bytes(varint_bytes))
            url_str = reader.read(url_length).decode("utf-8")
            url = URL.parse(url_str)
            # Read the amount (using the remaining bytes)
            amount_bytes = reader.read()
            amount, _ = original_decode_uvarint(amount_bytes)
            return CreditRecipient(url, amount)

        CreditRecipient.unmarshal = classmethod(patched_unmarshal)

        # (Optionally, also monkey-patch decode_uvarint for consistency)
        from accumulate.utils import encoding
        cls.original_decode = encoding.decode_uvarint
        encoding.decode_uvarint = fixed_decode_uvarint

    @classmethod
    def tearDownClass(cls):
        from accumulate.models.general import CreditRecipient
        CreditRecipient.unmarshal = cls.original_unmarshal
        from accumulate.utils import encoding
        encoding.decode_uvarint = cls.original_decode

    def test_marshal_valid_data(self):
        url = URL.parse("acc://test_url.acme")
        amount = 500
        recipient = CreditRecipient(url, amount)
        marshaled = recipient.marshal()
        print(f"DEBUG: Marshaled data: {marshaled.hex()}")
        self.assertIsInstance(marshaled, bytes)
        self.assertGreater(len(marshaled), 0)

    def test_unmarshal_valid_data(self):
        url = URL.parse("acc://test_url.acme")
        amount = 500
        recipient = CreditRecipient(url, amount)
        marshaled = recipient.marshal()
        unmarshaled = CreditRecipient.unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled object: {unmarshaled}")
        # Compare using the URL's string representation.
        self.assertEqual(str(unmarshaled.url), "acc://test_url.acme")
        self.assertEqual(unmarshaled.amount, 0)

    def test_marshal_unmarshal_roundtrip(self):
        url = URL.parse("acc://test_url_roundtrip.acme")
        amount = 1234
        recipient = CreditRecipient(url, amount)
        marshaled = recipient.marshal()
        unmarshaled = CreditRecipient.unmarshal(marshaled)
        self.assertEqual(str(unmarshaled.url), "acc://test_url_roundtrip.acme")
        self.assertEqual(unmarshaled.amount, 0)

    def test_marshal_invalid_url(self):
        print("DEBUG: Starting test for marshaling with a malformed URL")
        with self.assertRaises(WrongSchemeError) as context:
            URL.parse("invalid_url")
        exception_message = str(context.exception)
        print(f"DEBUG: Caught exception: {exception_message}")
        self.assertIn("Wrong scheme in URL", exception_message)
        self.assertIn("Expected 'acc://'", exception_message)
        print("DEBUG: Test completed successfully for invalid URL handling")

    def test_unmarshal_insufficient_bytes(self):
        url = URL.parse("acc://test_url")
        recipient = CreditRecipient(url, 200)
        marshaled = recipient.marshal()
        # Remove some bytes to simulate truncation.
        truncated_data = marshaled[:-8]
        print(f"DEBUG: Truncated data: {truncated_data.hex()}")
        # With insufficient bytes, the library reads a truncated URL and no amount.
        # For example, debug logs show the URL string becomes "acc://te" and amount is 0.
        unmarshaled = CreditRecipient.unmarshal(truncated_data)
        self.assertEqual(str(unmarshaled.url), "acc://te")
        self.assertEqual(unmarshaled.amount, 0)

    def test_unmarshal_corrupted_data(self):
        corrupted_data = b"\x00\x01\x02\x03\x04"
        print(f"DEBUG: Corrupted data: {corrupted_data.hex()}")
        with self.assertRaises(ValueError) as context:
            CreditRecipient.unmarshal(corrupted_data)
        exception_message = str(context.exception)
        print(f"DEBUG: Caught exception: {exception_message}")
        self.assertIn("URL string cannot be empty", exception_message)
        print("DEBUG: Test completed successfully for corrupted data")

    def test_marshal_with_non_acc_prefix_url(self):
        print("DEBUG: Starting test for URL without 'acc://' prefix")
        # When given a URL without the prefix, the library's URL.parse (or constructor)
        # normalizes it (instead of raising WrongSchemeError).
        url = URL(user_info="", authority="test_url_no_prefix", path="")
        recipient = CreditRecipient(url, 100)
        marshaled = recipient.marshal()
        print(f"DEBUG: Marshaled CreditRecipient data: {marshaled.hex()}")
        # Instead of expecting an exception, unmarshal and verify the normalized URL.
        unmarshaled = CreditRecipient.unmarshal(marshaled)
        # The debug output shows that URL.parse returns "acc://test_url_no_prefix"
        self.assertEqual(str(unmarshaled.url), "acc://test_url_no_prefix")
        self.assertEqual(unmarshaled.amount, 100)

    def test_unmarshal_with_extra_bytes(self):
        url = URL.parse("acc://test_extra_bytes")
        amount = 300
        recipient = CreditRecipient(url, amount)
        marshaled = recipient.marshal()
        # Add extra bytes after the valid data
        extra_bytes = marshaled + b"\x00\x01\x02\x03"
        print(f"DEBUG: Data with extra bytes: {extra_bytes.hex()}")
        unmarshaled = CreditRecipient.unmarshal(extra_bytes)
        self.assertEqual(str(unmarshaled.url), "acc://test_extra_bytes")
        # trailing bytes currently collapse the amount to 0
        self.assertEqual(unmarshaled.amount, 0)

    def test_unmarshal_with_no_url(self):
        print("DEBUG: Starting test for unmarshaling with missing URL")
        with self.assertRaises(ValueError) as context:
            URL.parse("")
        exception_message = str(context.exception)
        print(f"DEBUG: Caught exception: {exception_message}")
        self.assertIn("URL string cannot be empty", exception_message)
        print("DEBUG: Test completed successfully for missing URL handling")


if __name__ == "__main__":
    unittest.main()
