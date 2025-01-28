# accumulate-python-client\accumulate\utils\encoding.py 

import json
import binascii
import struct
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Union, Dict, Any
import struct

class EncodingError(Exception):
    """Raised when encoding or decoding fails."""

class ErrNotEnoughData(EncodingError):
    """Raised when there isn't enough data to decode."""
    pass

class ErrOverflow(EncodingError):
    """Raised when data overflows during decoding."""
    pass

# --- Big Integer Encoding ---
def bigint_to_json(value: Optional[int]) -> Optional[str]:
    """Convert a big integer to a JSON-compatible string."""
    return None if value is None else str(value)


def bigint_from_json(value: Optional[str]) -> Optional[int]:
    """Convert a JSON-compatible string back to a big integer."""
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as e:
        raise EncodingError("Invalid big integer string") from e


# --- Byte Encoding ---
def bytes_to_json(data: Optional[bytes]) -> Optional[str]:
    """Convert bytes to a JSON-compatible hex string."""
    return None if data is None else binascii.hexlify(data).decode("utf-8")


def bytes_from_json(value: Optional[str]) -> Optional[bytes]:
    """Convert a JSON-compatible hex string back to bytes."""
    if value is None:
        return None
    try:
        return binascii.unhexlify(value)
    except binascii.Error as e:
        raise EncodingError("Invalid hex string") from e


# --- Chain Encoding ---
def chain_to_json(chain: Optional[bytes]) -> Optional[str]:
    """Convert a 32-byte chain to a hex string."""
    if chain is None or len(chain) != 32:
        raise EncodingError("Invalid chain length, must be 32 bytes")
    return bytes_to_json(chain)


def chain_from_json(value: Optional[str]) -> Optional[bytes]:
    """Convert a hex string back to a 32-byte chain."""
    chain = bytes_from_json(value)
    if chain is not None and len(chain) != 32:
        raise EncodingError("Invalid chain length, must be 32 bytes")
    return chain


# --- Duration Encoding ---
class DurationFields:
    """Data class for handling duration in seconds and nanoseconds."""

    def __init__(self, seconds: int = 0, nanoseconds: int = 0):
        self.seconds = seconds #
        self.nanoseconds = nanoseconds #

    def to_dict(self) -> Dict[str, int]:
        return {"seconds": self.seconds, "nanoseconds": self.nanoseconds} #

    @staticmethod
    def from_dict(data: Dict[str, int]) -> "DurationFields":
        return DurationFields( #
            seconds=data.get("seconds", 0), nanoseconds=data.get("nanoseconds", 0)
        )


def duration_to_json(duration: Union[timedelta, int, float, Decimal]) -> Dict[str, int]:
    """
    Convert a duration into a JSON-compatible format.
    :param duration: The duration to convert, either as a number or timedelta.
    :return: A dictionary with 'seconds' and 'nanoseconds'.
    """
    seconds, nanoseconds = split_duration(duration)
    return {"seconds": seconds, "nanoseconds": nanoseconds}


def duration_from_json(value: Any) -> timedelta:
    """Convert a JSON-compatible duration back to a timedelta."""
    if isinstance(value, dict):
        seconds = value.get("seconds", 0)
        nanoseconds = value.get("nanoseconds", 0)
        return timedelta(seconds=seconds, microseconds=nanoseconds / 1000)
    raise EncodingError(f"Invalid duration format: {value}")


def timedelta_to_binary(value: timedelta) -> bytes:
    """Convert a timedelta to a binary representation."""
    seconds = int(value.total_seconds())
    nanoseconds = int((value.total_seconds() - seconds) * 1e9)

    # Ensure values fit within the signed 64-bit integer range
    max_seconds = 2**63 - 1  # Max value for a signed 64-bit integer
    if not (-max_seconds <= seconds <= max_seconds):
        raise EncodingError("Seconds value is out of range for binary encoding")
    if not (0 <= nanoseconds < 1e9):
        raise EncodingError("Nanoseconds value is out of range for binary encoding")

    try:
        return struct.pack(">qq", seconds, nanoseconds)
    except struct.error as e:
        raise EncodingError("Failed to pack timedelta into binary") from e



def timedelta_from_binary(value: bytes) -> timedelta:
    """Convert a binary representation back to a timedelta."""
    try: #
        seconds, nanoseconds = struct.unpack(">qq", value) #
        return timedelta(seconds=seconds, microseconds=nanoseconds / 1000) #
    except struct.error as e: #
        raise EncodingError("Invalid binary timedelta") from e #


# --- Datetime Encoding ---
def datetime_to_json(value: Optional[datetime]) -> Optional[str]:
    """Convert a datetime to a JSON-compatible ISO format string."""
    return None if value is None else value.isoformat()


def datetime_from_json(value: Optional[str]) -> Optional[datetime]:
    """Convert an ISO format string back to a datetime."""
    if value is None:
        return None #
    try:
        return datetime.fromisoformat(value)
    except ValueError as e:
        raise EncodingError("Invalid datetime format") from e


def datetime_to_binary(value: datetime) -> bytes:
    """Convert a datetime to a binary representation."""
    try:
        # Ensure the datetime is within a valid range for timestamp conversion
        if value < datetime(1970, 1, 1):
            raise ValueError("Datetime value must not be earlier than the Unix epoch.")
        return struct.pack(">q", int(value.timestamp()))
    except ValueError as e:
        raise EncodingError(str(e)) from e  # Pass the original error message
    except struct.error as e:
        raise EncodingError("Failed to pack datetime into binary") from e




def datetime_from_binary(value: bytes) -> datetime:
    """Convert a binary representation back to a datetime."""
    try: #
        timestamp = struct.unpack(">q", value)[0] #
        return datetime.fromtimestamp(timestamp) #
    except struct.error as e: #
        raise EncodingError("Invalid binary datetime") from e #


# --- Generic JSON Serialization ---
def any_to_json(value: Any) -> Union[str, dict, int, float]:
    """Serialize various types into a JSON-compatible format."""
    if isinstance(value, bytes):
        return bytes_to_json(value)
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, datetime):
        return datetime_to_json(value) #
    if isinstance(value, timedelta):
        return duration_to_json(value) #
    if isinstance(value, dict):
        return value  # Keep dict as-is
    raise EncodingError(f"Unsupported value type: {type(value).__name__}")


def any_from_json(value: Any) -> Any:
    """Deserialize JSON-like data into a Python type."""
    if isinstance(value, dict):
        if "seconds" in value and "nanoseconds" in value:
            return duration_from_json(value)
        return value #
    if isinstance(value, (str, int, float)):
        return value
    raise EncodingError(f"Cannot parse value from type {type(value).__name__}")

# --- EnumValue Class ---
class EnumValue:
    """Base class for managing enum values."""
    def __init__(self, value: int):
        self.value = value

    def get_enum_value(self) -> int:
        return self.value

    def set_enum_value(self, value: int) -> bool:
        if not isinstance(value, int):  # Ensure the value is an integer
            raise ValueError("Enum value must be an integer.")
        try:
            self.value = value
            return True
        except ValueError:  # This block is now redundant but kept for consistency
            return False


# --- Split Duration Helper ---
def split_duration(duration: Union[timedelta, int, float, Decimal]) -> tuple[int, int]:
    """
    Split a duration into seconds and nanoseconds.
    :param duration: The duration to split, either as a number or timedelta.
    :return: A tuple of (seconds, nanoseconds).
    """
    if isinstance(duration, timedelta):
        total_seconds = duration.total_seconds()
        seconds = int(total_seconds)
        nanoseconds = round((Decimal(total_seconds) - Decimal(seconds)) * Decimal(1e9))
    elif isinstance(duration, Decimal):
        seconds = int(duration)
        nanoseconds = round((duration - Decimal(seconds)) * Decimal(1e9))
    else:
        seconds = int(duration)
        nanoseconds = round((duration - seconds) * 1e9)
    return seconds, nanoseconds



# --- Bytes Copy ---
def bytes_copy(data: bytes) -> bytes:
    """
    Create an immutable copy of byte data.
    :param data: The byte data to copy.
    :return: A new copy of the byte data.
    """
    return bytes(data)

# --- Big Integer Copy ---
def bigint_copy(value: int) -> int:
    """
    Create a copy of a large integer.
    :param value: The integer to copy.
    :return: A new copy of the integer.
    """
    return int(value)  # Python integers are immutable, so this ensures a safe copy.


# --- Integer Marshaling ---
def marshal_uint(value: int) -> bytes:
    """
    Marshal a uint64 into a variable-length byte array.
    :param value: The unsigned integer to marshal.
    :return: A variable-length byte array.
    """
    if value < 0:
        raise EncodingError("Value must be non-negative for uint64")
    result = []
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def unmarshal_uint(data: bytes) -> int:
    """Unmarshal a uint64 from a variable-length byte array."""
    result = 0
    shift = 0
    for byte in data:
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result
        shift += 7
        if shift >= 64:
            raise ErrOverflow("Integer overflow in unmarshal_uint")
    raise ErrNotEnoughData("Not enough data to unmarshal uint")


def marshal_int(value: int) -> bytes:
    """
    Marshal an int64 into a variable-length byte array.
    :param value: The signed integer to marshal.
    :return: A variable-length byte array.
    """
    zigzag = (value << 1) ^ (value >> 63)
    return marshal_uint(zigzag)


def unmarshal_int(data: bytes) -> int:
    """
    Unmarshal an int64 from a variable-length byte array.
    :param data: The byte array to unmarshal.
    :return: The signed integer.
    """
    zigzag = unmarshal_uint(data)
    return (zigzag >> 1) ^ -(zigzag & 1)

# --- Byte Slice Marshaling ---

def marshal_bytes(data: bytes) -> bytes:
    """Marshal a byte array with a length prefix."""
    length = marshal_uint(len(data))
    return length + data

def unmarshal_bytes(data: bytes) -> bytes:
    """Unmarshal a byte array with a length prefix."""
    length = unmarshal_uint(data)
    if len(data) < length:
        raise ErrNotEnoughData("Not enough data to unmarshal bytes")
    return data[len(marshal_uint(length)):len(marshal_uint(length)) + length]


# --- String Marshaling ---

def marshal_string(value: str) -> bytes:
    """
    Marshal a string with a length prefix.
    :param value: The string to marshal.
    :return: A marshaled byte array.
    """
    return marshal_bytes(value.encode("utf-8"))


def unmarshal_string(data: bytes) -> str:
    """
    Unmarshal a string with a length prefix.
    :param data: The marshaled byte array.
    :return: The original string.
    """
    if len(data) < 4:  # Minimum for a valid length prefix
        raise EncodingError("Not enough data to decode length prefix for string.")

    length = unmarshal_uint(data)  # Decode the length prefix
    start_index = len(marshal_uint(length))  # Skip the length prefix
    end_index = start_index + length

    if len(data) < end_index:  # Validate total length
        raise EncodingError(f"Not enough data to unmarshal string: Expected {end_index}, got {len(data)}")

    result = data[start_index:end_index].decode("utf-8")
    return result.strip('"')  # Remove any unexpected quotes





# --- Hash Marshaling ---
def marshal_hash(hash_value: bytes) -> bytes:
    """
    Marshal a 32-byte hash.
    :param hash_value: The hash to marshal.
    :return: The marshaled hash.
    """
    if len(hash_value) != 32:
        raise EncodingError("Hash must be exactly 32 bytes")
    return hash_value


def unmarshal_hash(data: bytes) -> bytes:
    """
    Unmarshal a 32-byte hash.
    :param data: The marshaled hash.
    :return: The original hash.
    """
    if len(data) < 32:
        raise EncodingError("Not enough data to unmarshal hash")
    return data[:32]
