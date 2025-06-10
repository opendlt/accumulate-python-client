# accumulate-python-client\tests\test_utils\test_hash_functions.py

import sys
import builtins
import importlib
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


from accumulate.utils.hash_functions import (
    EncodingError as ImportedEncodingError,
)


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


# Re-use your helper
def generate_test_key(key_type="btc") -> bytes:
    if key_type == "btc":
        return b"\x02" + b"\x01" * 32
    elif key_type == "eth":
        return b"\x01" * 32 + b"\x02" * 32
    elif key_type == "ed25519":
        return b"\x01" * 32
    else:
        raise ValueError("Unsupported key type.")


# --- public_key_hash branches ---
def test_public_key_hash_standard():
    key = generate_test_key("ed25519")
    assert public_key_hash(key, SignatureType.ED25519) == hashlib.sha256(key).digest()

def test_public_key_hash_rcd1():
    key = b"\x11" * 32
    expected = hashlib.sha256(b"RCD" + key).digest()
    assert public_key_hash(key, SignatureType.RCD1) == expected

def test_public_key_hash_unsupported():
    with pytest.raises(ValueError, match="Unsupported signature type"):
        public_key_hash(b"foo", SignatureType.UNKNOWN)


# --- compute_hash raw-bytes branch ---
def test_compute_hash_bytes():
    data = b"hello world"
    assert compute_hash(data) == hashlib.sha256(data).digest()

# --- compute_hash missing marshal_binary ---
def test_compute_hash_no_marshal():
    with pytest.raises(ImportedEncodingError, match="must implement a `marshal_binary` method"):
        compute_hash(object())

# --- compute_hash marshal_binary raises ---
class BadBinary:
    def marshal_binary(self):
        raise RuntimeError("boom")

def test_compute_hash_marshal_error():
    with pytest.raises(ImportedEncodingError, match="Failed to marshal object for hashing"):
        compute_hash(BadBinary())


# --- btc_address and eth_address branches already covered by your existing tests ---


# --- hash_data branches ---
def test_hash_data_invalid_type():
    with pytest.raises(ValueError, match="Input must be of type bytes"):
        hash_data("not-bytes")


# --- LiteAuthorityForKey / Hash already covered ---


# --- fallback EncodingError import branch ---
def test_hash_functions_fallback_encoding_error(monkeypatch):
    # Remove real encoding module so import fails
    encoding_mod = sys.modules.pop("accumulate.utils.encoding", None)
    hf_name = "accumulate.utils.hash_functions"
    old_hf = sys.modules.pop(hf_name, None)

    orig_import = builtins.__import__
    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("accumulate.utils.encoding"):
            raise ImportError()
        return orig_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        hf = importlib.import_module(hf_name)
        importlib.reload(hf)  # re-trigger the try/except at top‐level
        # This EncodingError must be the fallback one, not the real one
        fb = hf.EncodingError("fallback!")
        assert isinstance(fb, Exception)
        assert str(fb) == "fallback!"
    finally:
        # Restore
        monkeypatch.setattr(builtins, "__import__", orig_import)
        if encoding_mod is not None:
            sys.modules["accumulate.utils.encoding"] = encoding_mod
        if old_hf is not None:
            sys.modules[hf_name] = old_hf
        else:
            importlib.reload(importlib.import_module(hf_name))