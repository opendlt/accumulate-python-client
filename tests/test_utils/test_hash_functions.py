# accumulate-python-client\tests\test_utils\test_hash_functions.py

import pytest
import hashlib
from eth_utils import keccak
import base58
from accumulate.models.signature_types import SignatureType
from accumulate.utils.hash_functions import (
    public_key_hash,
    compute_hash,
    btc_address,
    eth_address,
    hash_data,
    LiteAuthorityForKey,
    LiteAuthorityForHash,
)
from accumulate.utils.encoding import EncodingError


# Helper Function
def generate_test_key(key_type="btc") -> bytes:
    """
    Generate a valid test public key based on the key type.
    :param key_type: The type of key to generate ('btc' or 'eth').
    :return: A valid public key.
    """
    if key_type == "btc":
        return b"\x02" + b"\x01" * 32  # Prefix 0x02 for compressed keys
    elif key_type == "eth":
        return b"\x01" * 32 + b"\x02" * 32  # 64-byte uncompressed key
    elif key_type == "ed25519":
        return b"\x01" * 32  # Ed25519 public key
    else:
        raise ValueError("Unsupported key type. Use 'btc', 'eth', or 'ed25519'.")


# Tests for `public_key_hash`
def test_public_key_hash_valid():
    key = generate_test_key("ed25519")
    result = public_key_hash(key, SignatureType.ED25519)
    assert result == hashlib.sha256(key).digest()


def test_public_key_hash_btc():
    key = generate_test_key("btc")
    sha256_hash = hashlib.sha256(key).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_hash)
    result = public_key_hash(key, SignatureType.BTC)
    assert result == ripemd160.digest()


def test_public_key_hash_eth():
    key = generate_test_key("eth")
    result = public_key_hash(key, SignatureType.ETH)
    assert result == keccak(key)[-20:]


def test_public_key_hash_invalid():
    with pytest.raises(ValueError, match="Unsupported signature type"):
        public_key_hash(b"invalid_key", SignatureType.UNKNOWN)


# Tests for `compute_hash`
class MockHashable:
    def marshal_binary(self):
        return b"hashme"


def test_compute_hash_valid():
    obj = MockHashable()
    result = compute_hash(obj)
    assert result == hashlib.sha256(b"hashme").digest()


def test_compute_hash_invalid():
    with pytest.raises(EncodingError, match="must implement a `marshal_binary` method"):
        compute_hash(object())


# Tests for `btc_address`
def test_btc_address_valid():
    key = generate_test_key("btc")
    address = btc_address(key)
    assert isinstance(address, str)
    assert len(address) > 0


def test_btc_address_invalid():
    with pytest.raises(ValueError, match="Invalid public key length for BTC"):
        btc_address(b"short_key")


# Tests for `eth_address`
def test_eth_address_valid():
    key = generate_test_key("eth")
    address = eth_address(key)
    assert address.startswith("0x")
    assert len(address) == 42


def test_eth_address_invalid():
    with pytest.raises(ValueError, match="Invalid public key length for ETH"):
        eth_address(b"short_key")


# Tests for `hash_data`
def test_hash_data_valid():
    data = b"test_data"
    result = hash_data(data)
    assert result == hashlib.sha256(data).digest()


def test_hash_data_invalid():
    with pytest.raises(ValueError, match="Input must be of type bytes"):
        hash_data("invalid_data")  # Pass string instead of bytes


# Tests for `LiteAuthorityForKey` and `LiteAuthorityForHash`
def test_lite_authority_for_key():
    key = generate_test_key("btc")
    authority = LiteAuthorityForKey(key, SignatureType.BTC)
    assert isinstance(authority, str)
    assert len(authority) > 0


def test_lite_authority_for_hash():
    key_hash = hashlib.sha256(b"key").digest()
    authority = LiteAuthorityForHash(key_hash)
    assert isinstance(authority, str)
    assert len(authority) > 0
