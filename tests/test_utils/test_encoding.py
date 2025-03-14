# accumulate-python-client\tests\test_utils\test_encoding.py

import io
import struct
import pytest
import json
import hashlib
from datetime import datetime, timedelta
from decimal import Decimal

from accumulate.utils.encoding import (
    EncodingError,
    ValueOutOfRangeException,
    InvalidHashLengthException,
    encode_uvarint,
    decode_uvarint,
    read_uvarint,
    encode_compact_int,
    field_marshal_binary,
    boolean_marshal_binary,
    string_marshal_binary,
    bytes_marshal_binary,
    hash_marshal_binary,
    big_int_to_bytes,
    big_number_marshal_binary,
    unmarshal_string,
    unmarshal_bytes,
    encode,
    encode_value,
    consume,
)

# --- Unsigned Varint Tests ---
def test_encode_uvarint():
    assert encode_uvarint(0) == b'\x00'
    assert encode_uvarint(1) == b'\x01'
    # 127 fits in one byte
    assert encode_uvarint(127) == b'\x7f'
    # 128 requires continuation byte
    assert encode_uvarint(128) == b'\x80\x01'

def test_decode_uvarint():
    for value in [0, 1, 127, 128, 300]:
        encoded = encode_uvarint(value)
        decoded, length = decode_uvarint(encoded)
        assert decoded == value
        assert length == len(encoded)

def test_read_uvarint():
    value = 300
    encoded = encode_uvarint(value)
    reader = io.BytesIO(encoded)
    assert read_uvarint(reader) == value

# --- Compact Integer Encoding ---
def test_encode_compact_int():
    # For 0, returns single byte 0
    assert encode_compact_int(0) == b'\x00'
    # For a nonzero value, e.g. 255, expect 1-byte length (0x01) plus the 1-byte representation
    expected = b'\x01' + b'\xff'
    assert encode_compact_int(255) == expected

# --- Field-based Encoding ---
def test_field_marshal_binary():
    val = b'\x01\x02'
    result = field_marshal_binary(1, val)
    expected = struct.pack("B", 1) + val
    assert result == expected

def test_field_marshal_binary_out_of_range():
    with pytest.raises(ValueOutOfRangeException):
        field_marshal_binary(0, b'\x00')  # field numbers must be between 1 and 32

# --- Boolean Encoding ---
def test_boolean_marshal_binary():
    # With field: should wrap the boolean byte
    result_true = boolean_marshal_binary(True, 2)
    expected_true = field_marshal_binary(2, b'\x01')
    assert result_true == expected_true
    # Without field: simply returns b'\x00' or b'\x01'
    result_false = boolean_marshal_binary(False)
    assert result_false == b'\x00'

# --- String Encoding ---
def test_string_marshal_binary():
    # Without field: returns uvarint(length) + UTF-8 bytes
    result = string_marshal_binary("test")
    expected = encode_uvarint(4) + b"test"
    assert result == expected

    # With field: wraps using field_marshal_binary
    result_field = string_marshal_binary("test", 3)
    expected_field = field_marshal_binary(3, encode_uvarint(4) + b"test")
    assert result_field == expected_field

# --- Bytes Encoding ---
def test_bytes_marshal_binary():
    data = b"data"
    result = bytes_marshal_binary(data)
    expected = encode_uvarint(len(data)) + data
    assert result == expected

    result_field = bytes_marshal_binary(data, 4)
    expected_field = field_marshal_binary(4, encode_uvarint(len(data)) + data)
    assert result_field == expected_field

# --- Hash Encoding ---
def test_hash_marshal_binary():
    valid_hash = b"\x00" * 32
    # Without field, returns same value
    result = hash_marshal_binary(valid_hash)
    assert result == valid_hash

    # With field, wraps the hash value
    result_field = hash_marshal_binary(valid_hash, 5)
    expected_field = field_marshal_binary(5, valid_hash)
    assert result_field == expected_field

    # Invalid length should raise an exception
    with pytest.raises(InvalidHashLengthException):
        hash_marshal_binary(b"\x00" * 31)

# --- Big Integer Encoding ---
def test_big_int_to_bytes():
    # 255 should be one byte
    assert big_int_to_bytes(255) == b'\xff'
    # 256 should be two bytes: 0x01 0x00
    assert big_int_to_bytes(256) == b'\x01\x00'

def test_big_number_marshal_binary():
    num = 256
    inner = encode_uvarint(len(big_int_to_bytes(num))) + big_int_to_bytes(num)
    result = big_number_marshal_binary(num, 6)
    expected = field_marshal_binary(6, inner)
    assert result == expected

# --- Stream-Based Decoding Helpers ---
def test_unmarshal_string():
    original = "hello"
    encoded = string_marshal_binary(original)
    reader = io.BytesIO(encoded)
    result = unmarshal_string(reader)
    assert result == original

def test_unmarshal_bytes():
    original = b"world"
    encoded = bytes_marshal_binary(original)
    reader = io.BytesIO(encoded)
    result = unmarshal_bytes(reader)
    assert result == original

# --- Object Encoding ---
def test_encode_value_int():
    result = encode_value(123)
    expected = encode_uvarint(123)
    assert result == expected

def test_encode_value_str():
    result = encode_value("test")
    expected = encode_uvarint(4) + b"test"
    assert result == expected

def test_encode_value_bytes():
    data = b"data"
    result = encode_value(data)
    expected = encode_uvarint(len(data)) + data
    assert result == expected

def test_encode_value_dict():
    # For a nested dict, encode() is called recursively.
    sub = {"b": 2}
    result = encode_value(sub)
    # For sub-dict, the keys are enumerated starting at 1:
    expected = encode_uvarint(1) + encode_value(2)
    assert result == expected

def test_encode_value_list():
    lst = [1, "a"]
    result = encode_value(lst)
    expected = encode_value(1) + encode_value("a")
    assert result == expected

def test_encode_dict():
    # When encoding a dictionary, items are enumerated in insertion order.
    target = {"a": 1}
    result = encode(target)
    expected = encode_uvarint(1) + encode_value(1)
    assert result == expected

def test_consume():
    collected = []
    def consumer(field_num, value):
        collected.append((field_num, value))
    target = {"x": 10, "y": "test"}
    consume(target, consumer)
    # Assuming insertion order is preserved
    expected = [(1, 10), (2, "test")]
    assert collected == expected

# --- Round-Trip Test ---
def test_encode_decode_roundtrip():
    # Use a complex dictionary containing different types
    target = {
        "number": 42,
        "text": "hello",
        "data": b"binary",
        "nested": {"inner": 99},
        "list": [1, "x"],
    }
    encoded = encode(target)
    # Since our encoding does not provide a full decoder for dictionaries,
    # we can at least verify that the encoded output is bytes and non-empty.
    assert isinstance(encoded, bytes)
    assert len(encoded) > 0

    # Decode the first field.
    reader = io.BytesIO(encoded)
    # Read field number (expected to be 1)
    field_num = read_uvarint(reader)
    # Then, decode the value (expected to be 42)
    value = read_uvarint(reader)
    assert field_num == 1
    assert value == 42
    