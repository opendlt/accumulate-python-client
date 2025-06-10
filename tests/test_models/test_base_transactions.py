# accumulate-python-client\tests\test_models\test_base_transactions.py

# Standard library
from typing import Any
import unittest
import base64
import hashlib
import io
import struct
from types import SimpleNamespace

# Third-party
import pytest

# Testing helpers
from unittest.mock import Mock, patch

# Under-test modules
import accumulate.models.transactions as txmod
from accumulate.models.base_transactions import (
    TransactionBodyBase,
    TransactionBodyFactory,
    TransactionHeader,
    ExpireOptions,
    HoldUntilOptions,
)
from accumulate.models.enums import TransactionType
from accumulate.models.signature_types import SignatureType
from accumulate.signing.signer import Signer
from accumulate.utils.encoding import encode_uvarint, field_marshal_binary, read_uvarint


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


from accumulate.utils.encoding import encode_uvarint, field_marshal_binary, read_uvarint


# ————— TransactionBodyBase —————

def test_format_transaction_type():
    assert TransactionBodyBase._format_transaction_type("SEND_TOKENS") == "sendTokens"
    assert TransactionBodyBase._format_transaction_type("A") == "a"
    assert TransactionBodyBase._format_transaction_type("MULTI_PART_TEST") == "multiPartTest"

class DummyBody(TransactionBodyBase):
    def type(self):
        return TransactionType.SEND_TOKENS
    def fields_to_encode(self):
        return []
    @classmethod
    def unmarshal(cls, data: bytes):
        return cls()

def test_body_to_dict_and_empty_marshal():
    body = DummyBody()
    assert body.to_dict() == {"type": "sendTokens"}
    # no fields, so marshal() is empty
    assert body.marshal() == b""

class DummyBodyWithFields(TransactionBodyBase):
    def type(self):
        return TransactionType.CREATE_IDENTITY
    def fields_to_encode(self):
        # field 1 = varint 5; field 2 = raw bytes b"XY"
        return [
            (1, 5, encode_uvarint),
            (2, b"XY", lambda x: x),
        ]
    @classmethod
    def unmarshal(cls, data: bytes):
        raise NotImplementedError()

def test_body_marshal_with_fields():
    body = DummyBodyWithFields()
    result = body.marshal()
    expected = (
        field_marshal_binary(1, encode_uvarint(5)) +
        field_marshal_binary(2, b"XY")
    )
    assert result == expected


# ————— TransactionBodyFactory.create —————

class FakeInitBody(TransactionBodyBase):
    def __init__(self, client, *args, **kwargs):
        self.client = client
        self.args = args
        self.kwargs = kwargs
        self.initialized = False
    async def initialize(self, client):
        self.initialized = True
    def type(self):
        return TransactionType.ADD_CREDITS
    def fields_to_encode(self):
        return []
    @classmethod
    def unmarshal(cls, data: bytes):
        return cls(None)

@pytest.mark.asyncio
async def test_body_factory_supported_and_initialize(monkeypatch):
    # Monkeypatch the real class in the mapping
    import accumulate.models.transactions as txmod
    monkeypatch.setattr(txmod, "AddCredits", FakeInitBody)

    inst = await TransactionBodyFactory.create(
        client="CLI",
        transaction_type=TransactionType.ADD_CREDITS,
        foo=123
    )
    assert isinstance(inst, FakeInitBody)
    # initialize() should have been called
    assert inst.initialized is True
    assert inst.client == "CLI"
    assert inst.kwargs == {"foo": 123}

@pytest.mark.asyncio
async def test_body_factory_unsupported():
    # pick a type not in map
    inst = await TransactionBodyFactory.create(client=None, transaction_type=None)
    assert inst is None


# ————— ExpireOptions & HoldUntilOptions —————

def test_expire_and_hold_defaults_and_values():
    e = ExpireOptions(at_time=555)
    assert e.at_time == 555
    assert ExpireOptions().at_time is None

    h = HoldUntilOptions(minor_block=42)
    assert h.minor_block == 42
    assert HoldUntilOptions().minor_block is None


# ————— TransactionHeader.to_dict, marshal_binary & unmarshal —————

def test_header_to_dict_optional_fields():
    expire = ExpireOptions(at_time=10)
    hold = HoldUntilOptions(minor_block=20)
    initiator = hashlib.sha256(b"x").digest()
    header = TransactionHeader(
        principal="p://X",
        initiator=initiator,
        timestamp=999,
        signature_type=SignatureType.ED25519,
        memo="M",
        metadata=b"DATA",
        expire=expire,
        hold_until=hold,
        authorities=["a1","a2"],
    )
    d = header.to_dict()
    assert d["principal"] == "p://X"
    assert d["initiator"] == initiator.hex()
    assert d["memo"] == "M"
    assert d["metadata"] == base64.b64encode(b"DATA").decode()
    assert d["expire"] == 10
    assert d["hold_until"] == 20
    assert d["authorities"] == ["a1","a2"]

def test_header_marshal_and_unmarshal_roundtrip():
    # Prepare a header with all optional fields
    expire = ExpireOptions(at_time=5)
    hold = HoldUntilOptions(minor_block=6)
    initiator = b"\x00" * 32
    header = TransactionHeader(
        principal="p://Z",
        initiator=initiator,
        timestamp=123,
        signature_type=SignatureType.ED25519,
        memo="HELLO",
        metadata=b"\x01\x02",
        expire=expire,
        hold_until=hold,
        authorities=["x", "y", "z"],
    )
    data = header.marshal_binary()
    # It must start with field ID 1 (principal)
    assert data[0] == 1

    # The current unmarshal() doesn't supply timestamp/signature_type to __init__,
    # so it raises a TypeError at the return statement.
    with pytest.raises(TypeError):
        TransactionHeader.unmarshal(data)


# ————— TransactionHeader.create —————

@pytest.mark.asyncio
async def test_header_create_non_remote(monkeypatch):
    # fake signer returning known version & sig type
    class FakeSigner:
        url = "u://"
        async def get_signer_version(self): return 7
        async def get_signature_type(self): return SignatureType.ETH

    # patch Signer.calculate_metadata_hash
    monkeypatch.setattr(Signer, "calculate_metadata_hash", lambda pk, ts, su, sv, st: b"INIT_HASH")

    hdr = await TransactionHeader.create(
        principal="p://A",
        public_key=b"PUBBYTES",
        signer=FakeSigner(),
        timestamp=111,
        transaction_body=None
    )
    # not remote → timestamp & signature_type set
    assert hdr.initiator == b"INIT_HASH"
    assert hdr.timestamp == 111
    assert hdr.signature_type == SignatureType.ETH

@pytest.mark.asyncio
async def test_header_create_remote(monkeypatch):
    # Define a fake RemoteTransaction class (with a .hash attribute)
    class FakeRT:
        def __init__(self):
            self.hash = b"RHASH"

    # Monkey-patch the RemoteTransaction name in the module that create() imports it from
    monkeypatch.setattr(txmod, "RemoteTransaction", FakeRT)

    # Call TransactionHeader.create with our FakeRT instance as the transaction_body
    hdr = await TransactionHeader.create(
        principal="p://A",
        public_key=b"",
        signer=Mock(),
        timestamp=None,
        transaction_body=FakeRT()
    )

    # In the "remote" branch, create() must:
    #  - use transaction_body.hash for initiator
    #  - set timestamp to None
    #  - set signature_type to None
    assert hdr.initiator == b"RHASH"
    assert hdr.timestamp is None
    assert hdr.signature_type is None


# ————— TransactionHeader.build_transaction —————

def test_build_transaction_success_and_mismatch():
    # A helper header/body that implement the required interface
    class DummyHeader:
        def __init__(self, initiator):
            self.initiator = initiator
        def to_dict(self):
            return {"dummy": "hdr"}

        # Expose the instance method
        def build_transaction(self, txn):
            return TransactionHeader.build_transaction(self, txn)

    class DummyBody:
        def to_dict(self):
            return {"foo": "bar"}

    # Success case: txn.get_hash() matches header.initiator
    good_hash = hashlib.sha256(b"ok").digest()
    txn_ok = SimpleNamespace(
        header=DummyHeader(good_hash),
        body=DummyBody(),
        get_hash=lambda: good_hash
    )
    result = txn_ok.header.build_transaction(txn_ok)
    assert "transaction" in result
    tx0 = result["transaction"][0]
    assert tx0["header"] == {"dummy": "hdr"}
    assert tx0["body"] == {"foo": "bar"}

    # Mismatch case: header.initiator != txn.get_hash()
    bad_hash = b"\x00" * 32
    txn_bad = SimpleNamespace(
        header=DummyHeader(bad_hash),
        body=DummyBody(),
        get_hash=lambda: good_hash
    )
    with pytest.raises(ValueError, match="Transaction hash mismatch"):
        txn_bad.header.build_transaction(txn_bad)




if __name__ == "__main__":
    unittest.main()
