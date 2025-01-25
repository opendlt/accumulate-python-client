# C:\Accumulate_Stuff\accumulate-python-client\tests\test_utils\test_encoding.py

from accumulate.models.signature_types import SignatureType
import pytest
import json
import binascii
from datetime import datetime, timedelta
from decimal import Decimal
from accumulate.utils.encoding import (
    EncodingError, bigint_to_json, bigint_from_json, bytes_to_json,
    bytes_from_json, chain_to_json, chain_from_json, duration_to_json,
    duration_from_json, timedelta_to_binary, timedelta_from_binary,
    datetime_to_json, datetime_from_json, datetime_to_binary, datetime_from_binary,
    any_to_json, any_from_json, EnumValue, split_duration,
    bytes_copy, bigint_copy, marshal_uint, unmarshal_uint, marshal_int,
    unmarshal_int, marshal_bytes, unmarshal_bytes, marshal_string,
    unmarshal_string, marshal_hash, unmarshal_hash
)

# --- Big Integer Encoding ---
def test_bigint_encoding():
    assert bigint_to_json(12345678901234567890) == "12345678901234567890"
    assert bigint_from_json("12345678901234567890") == 12345678901234567890

    assert bigint_to_json(None) is None
    assert bigint_from_json(None) is None

    with pytest.raises(EncodingError):
        bigint_from_json("invalid")


# --- Byte Encoding ---
def test_bytes_encoding():
    data = b"test"
    assert bytes_to_json(data) == "74657374"
    assert bytes_from_json("74657374") == data

    assert bytes_to_json(None) is None
    assert bytes_from_json(None) is None

    with pytest.raises(EncodingError):
        bytes_from_json("invalidhex")


# --- Chain Encoding ---
def test_chain_encoding():
    chain = b"test" * 8  # 32 bytes
    assert chain_to_json(chain) == "7465737474657374746573747465737474657374746573747465737474657374"
    assert chain_from_json("7465737474657374746573747465737474657374746573747465737474657374") == chain

    with pytest.raises(EncodingError):
        chain_to_json(b"short")

    with pytest.raises(EncodingError):
        chain_from_json("74657374")


# --- Duration Encoding ---
def test_duration_encoding():
    duration = timedelta(seconds=3600, microseconds=123456)
    duration_json = duration_to_json(duration)
    assert duration_json == {"seconds": 3600, "nanoseconds": 123456000}

    restored_duration = duration_from_json(duration_json)
    assert restored_duration == duration

    with pytest.raises(EncodingError):
        duration_from_json("invalid")


# --- Datetime Encoding ---
def test_datetime_encoding():
    dt = datetime(2025, 1, 1, 12, 0, 0)
    dt_json = datetime_to_json(dt)
    assert dt_json == "2025-01-01T12:00:00"

    restored_dt = datetime_from_json(dt_json)
    assert restored_dt == dt

    with pytest.raises(EncodingError):
        datetime_from_json("invalid")


# --- Generic JSON Serialization ---
def test_generic_json_serialization():
    assert any_to_json(b"test") == "74657374"
    assert any_to_json(123) == 123
    assert any_to_json({"key": "value"}) == {"key": "value"}

    with pytest.raises(EncodingError):
        any_to_json(object())

    assert any_from_json({"seconds": 3600, "nanoseconds": 123456000}) == timedelta(seconds=3600, microseconds=123456)
    assert any_from_json(123) == 123

    with pytest.raises(EncodingError):
        any_from_json(object())


# --- EnumValue ---
def test_enum_value():
    enum = EnumValue(1)
    assert enum.get_enum_value() == 1
    assert enum.set_enum_value(2) is True
    assert enum.get_enum_value() == 2


# --- Split Duration Helper ---
def test_split_duration():
    seconds, nanoseconds = split_duration(timedelta(seconds=3600, microseconds=123456))
    assert seconds == 3600
    assert nanoseconds == 123456000


# --- Byte Copy ---
def test_bytes_copy():
    data = b"test"
    copied = bytes_copy(data)
    assert copied == data
    assert len(copied) == len(data)

    large_data = b"test" * 1000
    copied_large_data = bytes_copy(large_data)
    assert copied_large_data == large_data
    assert copied_large_data != large_data.replace(b"test", b"TEST")


# --- Big Integer Copy ---
def test_bigint_copy():
    value = 1234567890
    copied = bigint_copy(value)
    assert copied == value


# --- Integer Marshaling ---
def test_integer_marshaling():
    value = 300
    marshaled = marshal_uint(value)
    assert unmarshal_uint(marshaled) == value

    marshaled_int = marshal_int(-300)
    assert unmarshal_int(marshaled_int) == -300

    with pytest.raises(EncodingError):
        unmarshal_uint(b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01")

    with pytest.raises(EncodingError):
        marshal_uint(-1)


# --- Byte Slice Marshaling ---
def test_byte_slice_marshaling():
    data = b"test"
    marshaled = marshal_bytes(data)
    assert unmarshal_bytes(marshaled) == data

    with pytest.raises(EncodingError):
        unmarshal_bytes(b"\x80")


# --- String Marshaling ---
def test_string_marshaling():
    value = "test"
    marshaled = marshal_string(value)
    assert unmarshal_string(marshaled) == value


# --- Hash Marshaling ---
def test_hash_marshaling():
    hash_value = b"test" * 8  # 32 bytes
    assert marshal_hash(hash_value) == hash_value
    assert unmarshal_hash(hash_value) == hash_value

    with pytest.raises(EncodingError):
        marshal_hash(b"short")

    with pytest.raises(EncodingError):
        unmarshal_hash(b"short")
