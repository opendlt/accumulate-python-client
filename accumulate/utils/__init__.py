# accumulate-python-client\accumulate\utils\__init__.py

import logging
import io
import struct

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

from .encoding import (
    ValueOutOfRangeException,
    InvalidHashLengthException,
    encode_uvarint,
    decode_uvarint,
    encode_compact_int,
    field_marshal_binary,
    boolean_marshal_binary,
    string_marshal_binary,
    bytes_marshal_binary,
    hash_marshal_binary,
    big_int_to_bytes,
    big_number_marshal_binary,
    read_uvarint,
    unmarshal_string,
    unmarshal_bytes
)



from .formatting import (
    format_ac1,
    format_as1,
    format_ac2,
    format_as2,
    format_ac3,
    format_as3,
    format_fa,
    format_fs,
    format_btc,
    format_eth,
    format_amount,
    format_big_amount,
)

from .hash_functions import (
    public_key_hash,
    compute_hash,
    btc_address,
    eth_address,
    hash_data,
)

from .url import URL

from .validation import (
    ValidationError,
    validate_accumulate_url,
    is_reserved_url,
    is_valid_adi_url,
)

__all__ = [
    "ValueOutOfRangeException",
    "InvalidHashLengthException",
    "encode_uvarint",
    "decode_uvarint",
    "encode_compact_int",
    "field_marshal_binary",
    "boolean_marshal_binary",
    "string_marshal_binary",
    "bytes_marshal_binary",
    "hash_marshal_binary",
    "big_int_to_bytes",
    "big_number_marshal_binary",
    "read_uvarint",
    "unmarshal_string",
    "unmarshal_bytes"

    # From formatting.py
    "format_ac1",
    "format_as1",
    "format_ac2",
    "format_as2",
    "format_ac3",
    "format_as3",
    "format_fa",
    "format_fs",
    "format_btc",
    "format_eth",
    "format_amount",
    "format_big_amount",

    # From hash_functions.py
    "public_key_hash",
    "compute_hash",
    "btc_address",
    "eth_address",
    "hash_data",

    # From url.py
    "URL",

    # From validation.py
    "ValidationError",
    "validate_accumulate_url",
    "is_reserved_url",
    "is_valid_adi_url",
]
