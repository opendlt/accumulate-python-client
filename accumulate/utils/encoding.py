#!/usr/bin/env python3
import io
import struct
import logging
import struct
import json
import hashlib
from typing import Any

logger = logging.getLogger(__name__)
MAX_VARINT_LEN_64 = 10

class EncodingError(Exception):
    def __init__(self, message="Encoding error occurred"):
        super().__init__(message)

class ValueOutOfRangeException(Exception):
    def __init__(self, field):
        self.field = field
        super().__init__(f"Field number is out of range [1, 32]: {field}")

class InvalidHashLengthException(Exception):
    def __init__(self):
        super().__init__("Invalid length, value is not a hash")

# --- Unsigned Varint Encoding & Decoding ---
def encode_uvarint(x: int) -> bytes:
    """Encodes an unsigned integer using varint encoding."""
    if x < 0:
        raise ValueError("Cannot encode negative value as unsigned varint")
    buf = []
    while x > 0x7F:
        buf.append((x & 0x7F) | 0x80)
        x >>= 7
    buf.append(x & 0x7F)
    result = bytes(buf)
    logger.debug(f"encode_uvarint: {result.hex()}")
    return result

def decode_uvarint(buf: bytes) -> tuple[int, int]:
    """Decodes an unsigned integer from a bytes object using varint encoding"""
    x = 0
    shift = 0
    for i, b in enumerate(buf):
        x |= (b & 0x7F) << shift
        if b < 0x80:
            return x, i + 1
        shift += 7
    return 0, 0

def read_uvarint(reader: io.BytesIO) -> int:
    """Reads an unsigned varint from a byte stream"""
    x = 0
    shift = 0
    while True:
        b = reader.read(1)
        if len(b) == 0:
            raise EOFError("Unexpected end of stream while reading uvarint")
        b_val = b[0]
        x |= (b_val & 0x7F) << shift
        if b_val < 0x80:
            break
        shift += 7
    return x

# --- Compact Integer Encoding (as used in the working example) ---
def encode_compact_int(value: int) -> bytes:
    """Encodes an integer in compact form: a one‑byte length followed by the big‑endian bytes"""
    if value == 0:
        return b'\x00'
    num_bytes = (value.bit_length() + 7) // 8
    result = bytes([num_bytes]) + value.to_bytes(num_bytes, byteorder='big')
    logger.debug(f"encode_compact_int: {result.hex()}")
    return result

# --- Field-based Encoding (Aligned with manual example) ---
def field_marshal_binary(field: int, val: bytes) -> bytes:
    """
    Encodes a field by writing its field number as one byte,
    then appending the provided value (which itself may already be length‑prefixed)
    """
    if field < 1 or field > 32:
        raise ValueOutOfRangeException(field)
    result = struct.pack("B", field) + val
    logger.debug(f"field_marshal_binary (field {field}): {result.hex()}")
    return result

# --- Boolean Encoding ---
def boolean_marshal_binary(b: bool, field: int = None) -> bytes:
    data = b'\x01' if b else b'\x00'
    return field_marshal_binary(field, data) if field is not None else data

# --- String Encoding ---
def string_marshal_binary(val: str, field: int = None) -> bytes:
    utf8_data = val.encode("utf-8")
    data = encode_uvarint(len(utf8_data)) + utf8_data
    if field is not None:
        result = field_marshal_binary(field, data)
        logger.debug(f"string_marshal_binary (field {field}): {result.hex()}")
        return result
    else:
        logger.debug(f"string_marshal_binary (no field): {data.hex()}")
        return data

# --- Bytes Encoding ---
def bytes_marshal_binary(val: bytes, field: int = None) -> bytes:
    data = encode_uvarint(len(val)) + val
    if field is not None:
        result = field_marshal_binary(field, data)
        logger.debug(f"bytes_marshal_binary (field {field}): {result.hex()}")
        return result
    else:
        logger.debug(f"bytes_marshal_binary (no field): {data.hex()}")
        return data

# --- Hash Encoding ---
def hash_marshal_binary(val: bytes, field: int = None) -> bytes:
    if len(val) != 32:
        raise InvalidHashLengthException()
    if field is not None:
        return field_marshal_binary(field, val)
    return val

# --- Big Integer Encoding ---
def big_int_to_bytes(big_int: int) -> bytes:
    return big_int.to_bytes((big_int.bit_length() + 7) // 8, 'big')

def big_number_marshal_binary(num: int, field: int = None) -> bytes:
    bn_bytes = big_int_to_bytes(num)
    return bytes_marshal_binary(bn_bytes, field)

# --- Stream-Based Decoding Helpers ---
def unmarshal_string(reader: io.BytesIO) -> str:
    length = read_uvarint(reader)
    data = reader.read(length)
    return data.decode("utf-8")

def unmarshal_bytes(reader: io.BytesIO) -> bytes:
    length = read_uvarint(reader)
    return reader.read(length)


# ======= Methods Aligned to Python Initiator Approach ==========


def encode(target: dict) -> bytes:
    """
    Python equivalent of the JS encode() function
    Encodes an object into a binary format using uvarint encoding.
    """
    if not isinstance(target, dict):
        raise TypeError("encode() expects a dictionary as input")

    parts = bytearray()

    # Iterate through fields and encode each one
    for field_num, (key, value) in enumerate(target.items(), start=1):
        field_number_encoded = encode_uvarint(field_num)
        value_encoded = encode_value(value)
        
        parts.extend(field_number_encoded)  # Field number
        parts.extend(value_encoded)         # Encoded value

    return bytes(parts)

def encode_value(value: Any) -> bytes:
    """
    Encodes a single value based on its type
    Mirrors the encoding rules from the JavaScript library
    """
    if isinstance(value, int):
        return encode_uvarint(value)  # Variable-length encoding for numbers
    elif isinstance(value, str):
        value_bytes = value.encode("utf-8")
        return encode_uvarint(len(value_bytes)) + value_bytes
    elif isinstance(value, bytes):
        return encode_uvarint(len(value)) + value
    elif isinstance(value, dict):
        return encode(value)  # Recursive encoding for nested objects
    elif isinstance(value, list):
        encoded_list = bytearray()
        for item in value:
            encoded_list.extend(encode_value(item))
        return encoded_list
    else:
        raise TypeError(f"Unsupported data type: {type(value)}")

def consume(target: dict, consumer: callable):
    """
    Extracts fields from an object and applies the consumer function to each field
    Mirrors the JS `consume()` function
    """
    if not isinstance(target, dict):
        raise TypeError("consume() expects a dictionary as input")

    for field_num, (key, value) in enumerate(target.items(), start=1):
        consumer(field_num, value)

# Example usage:
signature_metadata = {
    "publicKey": "abcd1234",
    "timestamp": 1700000000000,
    "signer": "acc://some-url",
    "signerVersion": 1,
    "signatureType": "ED25519"
}

encoded_metadata = encode(signature_metadata)
metadata_hash = hashlib.sha256(encoded_metadata).digest()

print(f"Encoded Metadata: {encoded_metadata.hex()}")
print(f"Metadata Hash (SHA-256): {metadata_hash.hex()}")
