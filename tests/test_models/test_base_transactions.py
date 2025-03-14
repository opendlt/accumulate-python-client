# accumulate-python-client\tests\test_models\test_base_transactions.py

# accumulate-python-client/tests/test_models/test_base_transactions.py

from typing import Any
import unittest
from unittest.mock import Mock, patch
from accumulate.models.base_transactions import (
    TransactionBodyBase,
    TransactionHeader,
    ExpireOptions,
    HoldUntilOptions,
)
from accumulate.models.enums import TransactionType
from accumulate.models.signature_types import SignatureType  # New import for required param

class TestTransactionBody(unittest.TestCase):
    def test_transaction_body_abstract_methods(self):
        class DummyTransactionBody(TransactionBodyBase):
            def type(self) -> TransactionType:
                return TransactionType.SEND_TOKENS

            def fields_to_encode(self):
                # For testing, we return an empty list (or you could return dummy fields)
                return []

            def marshal(self) -> bytes:
                return b"dummy"

            def unmarshal(self, data: bytes) -> Any:
                return "unmarshalled"

        body = DummyTransactionBody()
        self.assertEqual(body.type(), TransactionType.SEND_TOKENS)
        self.assertEqual(body.marshal(), b"dummy")
        self.assertEqual(body.unmarshal(b"data"), "unmarshalled")

    def test_transaction_body_cannot_instantiate_directly(self):
        with self.assertRaises(TypeError):
            TransactionBodyBase()


class TestTransactionHeader(unittest.TestCase):
    def setUp(self):
        self.principal = "acc://example.com"
        self.initiator = b"initiator_hash"
        self.memo = "Test Transaction"
        self.metadata = b"metadata"
        self.expire = Mock(spec=ExpireOptions)
        self.hold_until = Mock(spec=HoldUntilOptions)
        self.authorities = ["acc://auth1", "acc://auth2"]

        # Provide required timestamp and signature_type
        self.timestamp = 1234567890
        self.signature_type = SignatureType.ED25519  # adjust as needed

        self.header = TransactionHeader(
            principal=self.principal,
            initiator=self.initiator,
            timestamp=self.timestamp,
            signature_type=self.signature_type,
            memo=self.memo,
            metadata=self.metadata,
            expire=self.expire,
            hold_until=self.hold_until,
            authorities=self.authorities,
        )

    def test_initialization(self):
        self.assertEqual(self.header.principal, self.principal)
        self.assertEqual(self.header.initiator, self.initiator)
        self.assertEqual(self.header.memo, self.memo)
        self.assertEqual(self.header.metadata, self.metadata)
        self.assertEqual(self.header.expire, self.expire)
        self.assertEqual(self.header.hold_until, self.hold_until)
        self.assertEqual(self.header.authorities, self.authorities)
        self.assertEqual(self.header.timestamp, self.timestamp)
        self.assertEqual(self.header.signature_type, self.signature_type)

    def test_default_values(self):
        # When only principal is provided, supply default timestamp and signature_type
        default_header = TransactionHeader(
            principal=self.principal,
            initiator=None,
            timestamp=0,
            signature_type=SignatureType.UNKNOWN,  # assuming UNKNOWN exists in your enum
        )
        self.assertIsNone(default_header.initiator)
        self.assertIsNone(default_header.memo)
        self.assertIsNone(default_header.metadata)
        self.assertIsNone(default_header.expire)
        self.assertIsNone(default_header.hold_until)
        self.assertEqual(default_header.authorities, [])

    @patch("accumulate.models.base_transactions.TransactionHeader.marshal_binary")
    def test_marshal_binary(self, mock_marshal):
        mock_marshal.return_value = b"serialized_header"
        self.assertEqual(self.header.marshal_binary(), b"serialized_header")
        mock_marshal.assert_called_once()

    @patch("accumulate.models.base_transactions.TransactionHeader.unmarshal")
    def test_unmarshal(self, mock_unmarshal):
        mock_unmarshal.return_value = self.header
        result = TransactionHeader.unmarshal(b"data")
        self.assertEqual(result, self.header)
        mock_unmarshal.assert_called_once_with(b"data")


class TestExpireOptions(unittest.TestCase):
    def test_initialization(self):
        expire = ExpireOptions(at_time=1234567890)
        self.assertEqual(expire.at_time, 1234567890)

        expire = ExpireOptions()
        self.assertIsNone(expire.at_time)


class TestHoldUntilOptions(unittest.TestCase):
    def test_initialization(self):
        hold = HoldUntilOptions(minor_block=42)
        self.assertEqual(hold.minor_block, 42)

        hold = HoldUntilOptions()
        self.assertIsNone(hold.minor_block)


if __name__ == "__main__":
    unittest.main()
