# accumulate-python-client\tests\test_models\test_protocol.py

import unittest
from decimal import Decimal
from hashlib import sha256
from datetime import timedelta
from accumulate.models.signature_types import SignatureType
from accumulate.models.protocol import (
    acme_url,
    unknown_url,
    lite_data_address,
    parse_lite_address,
    lite_token_address,
    LiteTokenAccount,
    TokenAccount,
    TokenIssuer,
    AllowedTransactions,
    Receipt,
)
from accumulate.utils.hash_functions import LiteAuthorityForKey, LiteAuthorityForHash
from accumulate.utils.encoding import (
    encode_uvarint,
    decode_uvarint,
    string_marshal_binary,
    unmarshal_string,
)
from accumulate.utils.url import URL, WrongSchemeError
import io
import logging

class TestProtocol(unittest.TestCase):

    def setUp(self):
        """Configure logging for the tests."""
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
        self.logger = logging.getLogger(__name__)

    def test_acme_url(self):
        """Test URL generation for ACME token."""
        self.assertEqual(acme_url().authority, "ACME")

    def test_unknown_url(self):
        """Test URL generation for unknown entities."""
        self.assertEqual(unknown_url().authority, "unknown")

    def test_lite_data_address_valid(self):
        """Test lite data address generation with valid chain ID."""
        chain_id = b"test_chain_id_32_bytes_long_12345678"
        result = lite_data_address(chain_id)
        self.assertIsInstance(result, URL)
        self.assertEqual(result.authority, chain_id.hex()[:32])

    def test_lite_data_address_invalid(self):
        """Test lite data address generation with invalid chain ID."""
        with self.assertRaises(ValueError):
            lite_data_address(b"short_chain_id")

    def test_parse_lite_address_valid(self):
        """Test parsing a valid lite address."""
        valid_authority = "1234567890abcdef1234567890abcdef56781234"
        checksum = sha256(bytes.fromhex(valid_authority)).digest()[-4:].hex()
        url = URL(authority=f"{valid_authority}{checksum}")
        result = parse_lite_address(url)
        self.assertEqual(result, bytes.fromhex(valid_authority))

    def test_parse_lite_address_invalid_checksum(self):
        """Test parsing a lite address with an invalid checksum."""
        invalid_authority = "1234567890abcdef1234567890abcdef56781234"
        url = URL(authority=f"{invalid_authority}badchecksum")
        with self.assertRaises(ValueError):
            parse_lite_address(url)

    def test_lite_token_address(self):
        """Test generating lite token account URL."""
        pub_key = b"test_public_key"
        # Valid ADI
        adi_url = "acc://DefiDevs.acme"
        result = lite_token_address(pub_key, adi_url)
        self.assertIsInstance(result, URL)

        # Valid lite token account
        lite_token_url = "acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56/ACME"
        result = lite_token_address(pub_key, lite_token_url)
        self.assertIsInstance(result, URL)

    def test_lite_token_address_invalid_token_url(self):
        """Test generating lite token account URL with invalid token URL."""
        pub_key = b"test_public_key"
        invalid_token_url = "invalid_url_without_proper_format"

        self.logger.debug(f"Testing lite_token_address with invalid URL: {invalid_token_url}")

        with self.assertRaises(ValueError) as context:
            lite_token_address(pub_key, invalid_token_url)

        self.assertIn("Invalid token URL", str(context.exception))
        self.assertIn("Missing path or invalid identity format", str(context.exception))

    def test_url_parse_invalid_format(self):
        """Test parsing an invalid URL format."""
        invalid_url = "invalid_url_without_proper_format"

        with self.assertRaises(WrongSchemeError) as context:
            URL.parse(invalid_url)

        self.assertIn("Wrong scheme in URL", str(context.exception))
        self.logger.debug(f"Exception raised as expected: {context.exception}")

    def test_account_with_tokens_operations(self):
        """Test token account operations."""
        account = LiteTokenAccount(
            url=URL(authority="account.acme"), balance=Decimal("100"), token_url=acme_url()
        )
        self.assertTrue(account.credit_tokens(Decimal("50")))
        self.assertEqual(account.token_balance(), Decimal("150"))
        self.assertTrue(account.debit_tokens(Decimal("50")))
        self.assertEqual(account.token_balance(), Decimal("100"))
        self.assertFalse(account.debit_tokens(Decimal("200")))  # Insufficient balance

    def test_token_issuer_issue(self):
        """Test issuing tokens with and without a supply limit."""
        issuer = TokenIssuer(issued=Decimal("100"), supply_limit=Decimal("200"))
        self.assertTrue(issuer.issue(Decimal("50")))
        self.assertFalse(issuer.issue(Decimal("100")))  # Exceeds supply limit

        unlimited_issuer = TokenIssuer(issued=Decimal("100"))
        self.assertTrue(unlimited_issuer.issue(Decimal("10000")))

    def test_allowed_transactions(self):
        """Test allowed transactions bitmask operations."""
        allowed = AllowedTransactions()
        allowed.set(2)
        allowed.set(5)
        self.assertTrue(allowed.is_set(2))
        self.assertTrue(allowed.is_set(5))
        self.assertFalse(allowed.is_set(3))
        allowed.clear(2)
        self.assertFalse(allowed.is_set(2))
        self.assertEqual(allowed.unpack(), [5])

    def test_allowed_transactions_serialization(self):
        """Test serialization and deserialization of allowed transactions."""
        allowed = AllowedTransactions()
        allowed.set(1)
        allowed.set(4)
        json_data = allowed.to_json()
        self.assertEqual(json_data, "[1, 4]")

        deserialized = AllowedTransactions.from_json(json_data)
        self.assertTrue(deserialized.is_set(1))
        self.assertTrue(deserialized.is_set(4))

    def test_receipt_to_and_from_dict(self):
        """Test converting a receipt to and from a dictionary."""
        receipt = Receipt(local_block=1, local_block_time="2023-01-01T12:00:00", major_block=10)
        data = receipt.to_dict()
        self.assertEqual(data, {
            "local_block": 1,
            "local_block_time": "2023-01-01T12:00:00",
            "major_block": 10,
        })
        recreated = Receipt.from_dict(data)
        self.assertEqual(recreated.local_block, 1)
        self.assertEqual(recreated.local_block_time, "2023-01-01T12:00:00")
        self.assertEqual(recreated.major_block, 10)

    def test_receipt_invalid_iso8601(self):
        """Test receipt creation with invalid ISO 8601 datetime."""
        with self.assertRaises(ValueError):
            Receipt.from_dict({"local_block_time": "invalid_datetime"})

    def test_lite_authority_for_key(self):
        """Test generating lite authority for a public key."""
        pub_key = b"test_public_key"
        authority = LiteAuthorityForKey(pub_key, SignatureType.ED25519)
        self.assertTrue(len(authority) > 0)

    def test_lite_authority_for_hash(self):
        """Test generating lite authority for a key hash."""
        key_hash = sha256(b"test_key").digest()
        authority = LiteAuthorityForHash(key_hash)
        self.assertEqual(len(authority), 40 + 8)  # Key hash (40 hex chars) + checksum (8 hex chars)

    def test_marshal_and_unmarshal_uint(self):
        """Test encoding and decoding of unsigned integers."""
        value = 12345
        marshaled = encode_uvarint(value)
        unmarshaled, _ = decode_uvarint(marshaled)
        self.assertEqual(value, unmarshaled)

    def test_marshal_and_unmarshal_string(self):
        """Test encoding and decoding of strings."""
        value = "test_string"
        marshaled = string_marshal_binary(value)
        # Wrap the bytes in a BytesIO for reading
        reader = io.BytesIO(marshaled)
        unmarshaled = unmarshal_string(reader)
        self.assertEqual(value, unmarshaled)

if __name__ == "__main__":
    unittest.main()
