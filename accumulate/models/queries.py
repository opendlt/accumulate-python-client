# accumulate-python-client\accumulate\models\queries.py

from typing import Optional, Union, Dict
from accumulate.models.enums import QueryType
from accumulate.models.options import RangeOptions, ReceiptOptions
from accumulate.models.signature_types import SignatureType
import base64
import base58
import re
import logging

logger = logging.getLogger(__name__)

class AccumulateError(Exception):
    """Base class for all custom exceptions in the Accumulate client."""
    pass

from accumulate.utils.address_parse import parse_mh_address
class Query:
    """Base class for all query types."""

    def __init__(self, query_type: QueryType, params: Optional[dict] = None):
        self.query_type = query_type
        self.params = params or {}

    def is_valid(self) -> bool:
        """Validate the query parameters."""
        return bool(self.query_type)

    def to_dict(self) -> dict:
        """Convert the query to a dictionary ensuring queryType is formatted correctly."""
        query_dict = {
            "queryType": self.query_type.to_rpc_format(),  # Convert to lowercase string
        }
        query_dict.update(self.params)  # Merge additional parameters
        return query_dict


class DefaultQuery(Query):
    """Represents the default query type."""

    def __init__(self, include_receipt: Optional[ReceiptOptions] = None):
        super().__init__(QueryType.DEFAULT)
        self.include_receipt = include_receipt

    def is_valid(self):
        """Validate the default query."""
        if self.include_receipt and not (
            self.include_receipt.for_any or self.include_receipt.for_height is not None
        ):
            raise AccumulateError("Invalid ReceiptOptions: Must specify `for_any` or `for_height`.")


    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "include_receipt": self.include_receipt.to_dict() if self.include_receipt else None,
        })
        return data


class ChainQuery(Query):
    """Represents a chain query."""

    def __init__(
        self,
        name: Optional[str] = None,
        index: Optional[int] = None,
        entry: Optional[bytes] = None,
        range: Optional[RangeOptions] = None,
        include_receipt: Optional[ReceiptOptions] = None,
    ):
        super().__init__(QueryType.CHAIN)
        self.name = name
        self.index = index
        self.entry = entry
        self.range = range
        self.include_receipt = include_receipt

    def is_valid(self):
        """Validate the chain query."""
        if self.range and (self.index or self.entry):
            raise AccumulateError("Range is mutually exclusive with index and entry.")
        if not self.name and (self.index or self.entry or self.range):
            raise AccumulateError("Name is required when querying by index, entry, or range.")
        if self.include_receipt and not self.include_receipt.is_valid():
            raise AccumulateError("Invalid ReceiptOptions.")


    def to_dict(self) -> dict:
        """Ensure `name` is always included in the query."""
        data = super().to_dict()
        data.update({
            "name": self.name if self.name else "main",
            "index": self.index,
            "entry": self.entry,
            "range": self.range.to_dict() if self.range else None,
            "include_receipt": self.include_receipt.to_dict() if self.include_receipt else None,
        })
        return data




class DataQuery(Query):
    """Represents a data query."""

    def __init__(
        self,
        index: Optional[int] = None,
        entry: Optional[bytes] = None,
        range: Optional[RangeOptions] = None,
    ):
        super().__init__(QueryType.DATA)
        self.index = index
        self.entry = entry
        self.range = range

    def is_valid(self):
        """Validate the data query."""
        if self.range and (self.index or self.entry):
            raise AccumulateError("Range is mutually exclusive with index and entry.")

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "index": self.index,
            "entry": self.entry,
            "range": self.range.to_dict() if self.range else None,
        })
        return data


class DirectoryQuery(Query):
    """Represents a directory query."""

    def __init__(self, range: Optional[RangeOptions] = None):
        super().__init__(QueryType.DIRECTORY)
        self.range = range

    def is_valid(self):
        """Validate the directory query."""
        if self.range and not (
            self.range.start is not None or self.range.count is not None
        ):
            raise AccumulateError("Invalid RangeOptions: Must include `start` or `count`.")

    def to_dict(self) -> dict:
        """Ensure the query outputs correctly formatted range parameters."""
        data = super().to_dict()
        
        #  Always include `range` (Fix for API error)
        data["range"] = {
            "start": self.range.start if self.range and self.range.start is not None else 0,
            "count": self.range.count if self.range and self.range.count is not None else 10,
            "from_end": self.range.from_end if self.range and self.range.from_end is not None else False,
            "expand": self.range.expand if self.range and self.range.expand is not None else False,
        }

        return data



class PendingQuery(Query):
    """Represents a pending query."""

    def __init__(self, range: Optional[RangeOptions] = None):
        super().__init__(QueryType.PENDING)
        self.range = range

    def is_valid(self):
        """Validate the pending query."""
        if self.range and not (
            self.range.start is not None or self.range.count is not None
        ):
            raise AccumulateError("Invalid RangeOptions: Must include `start` or `count`.")

    def to_dict(self) -> dict:
        """Ensure the query outputs correctly formatted range parameters."""
        data = super().to_dict()
        
        #  Always include `range` (Fix for API error)
        data["range"] = {
            "start": self.range.start if self.range and self.range.start is not None else 0,
            "count": self.range.count if self.range and self.range.count is not None else 10,
            "from_end": self.range.from_end if self.range and self.range.from_end is not None else False,
            "expand": self.range.expand if self.range and self.range.expand is not None else False,
        }

        return data



class BlockQuery(Query):
    """Represents a block query."""

    def __init__(
        self,
        minor: Optional[int] = None,
        major: Optional[int] = None,
        minor_range: Optional[RangeOptions] = None,
        major_range: Optional[RangeOptions] = None,
        entry_range: Optional[RangeOptions] = None,
        omit_empty: Optional[bool] = None,
    ):
        super().__init__(QueryType.BLOCK)
        self.minor = minor
        self.major = major
        self.minor_range = minor_range
        self.major_range = major_range
        self.entry_range = entry_range
        self.omit_empty = omit_empty

    def is_valid(self):
        """Validate the block query. Ensure at least one required field is set."""
        if not (self.minor or self.major or self.minor_range or self.major_range):
            raise AccumulateError(
                "BlockQuery must specify at least one of: minor, major, minor_range, or major_range."
            )
        if self.minor and self.minor_range:
            raise AccumulateError("Cannot specify both minor and minor_range.")
        if self.major and self.major_range:
            raise AccumulateError("Cannot specify both major and major_range.")
        if self.entry_range and (self.minor_range or self.major_range):
            raise AccumulateError("EntryRange cannot be used with minor/major ranges.")
        if self.entry_range and not (self.entry_range.start or self.entry_range.count):
            raise AccumulateError("EntryRange must specify `start` or `count`.")

    def to_dict(self) -> dict:
        """Convert BlockQuery to the API-compatible format."""
        data = super().to_dict()
        query_params = {}

        if self.minor is not None:
            query_params["minor"] = self.minor
        if self.major is not None:
            query_params["major"] = self.major
        if self.minor_range:
            query_params["minor_range"] = self.minor_range.to_dict()
        if self.major_range:
            query_params["major_range"] = self.major_range.to_dict()
        if self.entry_range:
            query_params["entry_range"] = self.entry_range.to_dict()
        if self.omit_empty is not None:
            query_params["omit_empty"] = self.omit_empty  # True/False

        data.update(query_params)
        return data


class AnchorSearchQuery(Query):
    """Represents an anchor search query."""

    def __init__(self, anchor: bytes, include_receipt: Optional[ReceiptOptions] = None):
        super().__init__(QueryType.ANCHOR_SEARCH)
        self.anchor = anchor
        self.include_receipt = include_receipt

    def is_valid(self):
        """Validate the anchor search query."""
        if not self.anchor:
            raise AccumulateError("Anchor is required for an anchor search query.") #
        if self.include_receipt and not (
            self.include_receipt.for_any or self.include_receipt.for_height is not None
        ):
            raise AccumulateError("Invalid ReceiptOptions: Must specify `for_any` or `for_height`.") #

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "anchor": self.anchor.hex() if self.anchor else None,
            "include_receipt": self.include_receipt.to_dict() if self.include_receipt else None,
        })
        return data


class PublicKeySearchQuery(Query):
    """Represents a public key search query."""

    def __init__(self, public_key: str, signature_type: Optional[Union[int, SignatureType]] = SignatureType.ED25519):
        super().__init__(QueryType.PUBLIC_KEY_SEARCH)

        logger.debug(f" Received Public Key: {public_key}")

        #  Auto-detect and convert the public key to HEX format
        self.public_key = self._convert_to_hex(public_key)

        #  Ensure signature_type is stored as a SignatureType enum and converted to RPC format
        if isinstance(signature_type, int):
            self.signature_type = SignatureType.from_value(signature_type)
        elif isinstance(signature_type, SignatureType):
            self.signature_type = signature_type
        else:
            raise ValueError(f"Invalid signature type: {signature_type}")

    def _convert_to_hex(self, public_key: str) -> bytes:
        """Detect and convert the provided public key to HEX."""
        if public_key.startswith("MH"):  
            parsed = parse_mh_address(public_key)
            if not isinstance(parsed.hash, bytes):
                raise ValueError(f" Invalid MH address: {public_key}")
            logger.debug(f" Parsed MH public key: {parsed.hash.hex()}")
            return parsed.hash

        elif public_key.startswith("0x"):  
            logger.debug(f" Parsed hex address: {public_key[2:]}")
            return bytes.fromhex(public_key[2:])  #  Remove '0x' and convert hex

        elif re.fullmatch(r"[0-9a-fA-F]+", public_key):  
            logger.debug(f" Parsed raw hex: {public_key}")
            return bytes.fromhex(public_key)  #  Convert raw hex

        else:
            try:
                #  Convert Base58 public key to HEX
                decoded_bytes = base58.b58decode(public_key)  
                logger.debug(f" Parsed Base58 public key (converted to HEX): {decoded_bytes.hex()}")
                return decoded_bytes  # Store as bytes
            except Exception as e:
                logger.error(f" Invalid public key format: {public_key}, Error: {e}")
                raise ValueError(f"Invalid public key format: {public_key}")

    def is_valid(self):
        """Validate the public key search query."""
        if not self.public_key:
            logger.error(" Public key is required for a public key search query.")
            raise AccumulateError("Public key is required for a public key search query.")
        if not isinstance(self.signature_type, SignatureType):
            logger.error(" Signature type must be a valid SignatureType enum.")
            raise AccumulateError("Signature type must be a valid SignatureType enum.")

    def to_dict(self) -> dict:
        """Ensure the query outputs HEX for `publicKey` and correctly formatted `Type` field."""
        public_key_hex = self.public_key.hex()  #  Convert bytes to HEX
        signature_type_rpc = self.signature_type.to_rpc_format()  #  Convert signature type to expected RPC format

        logger.debug(f" FINAL HEX public key before sending: {public_key_hex}")  
        logger.debug(f" FINAL SignatureType before sending: {signature_type_rpc}")  

        return {
            "queryType": "publicKeySearch",  #  Explicit string
            "publicKey": public_key_hex,  #  Send HEX, NOT Base58
            "Type": signature_type_rpc,  #  Send SignatureType as a string
        }


class PublicKeyHashSearchQuery(Query):
    """Represents a public key hash search query."""

    def __init__(self, public_key_hash: str):
        super().__init__(QueryType.PUBLIC_KEY_HASH_SEARCH)
        self.public_key_hash = public_key_hash

    def is_valid(self):
        """Validate the public key hash search query."""
        if not self.public_key_hash:
            raise AccumulateError("Public key hash is required for a public key hash search query.")

    def to_dict(self) -> dict:
        """Convert the query to a dictionary ensuring correct JSON-RPC format."""
        return {
            "queryType": self.query_type.to_rpc_format(),  #  Ensure camelCase format
            "publicKeyHash": self.public_key_hash,  #  Ensure hex format (string)
        }



class DelegateSearchQuery(Query):
    """Represents a delegate search query."""

    def __init__(self, delegate: str):
        super().__init__(QueryType.DELEGATE_SEARCH)
        self.delegate = delegate

    def is_valid(self):
        """Validate the delegate search query."""
        if not self.delegate:
            raise AccumulateError("Delegate is required for a delegate search query.") #
        # Additional validation for delegate (e.g., valid URL format) could be added.

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "delegate": self.delegate,
        })
        return data


class MessageHashSearchQuery(Query):
    """Represents a message hash search query."""

    def __init__(self, hash: bytes):
        super().__init__(QueryType.MESSAGE_HASH_SEARCH)
        self.hash = hash

    def is_valid(self):
        """Validate the message hash search query."""
        if not self.hash:
            raise AccumulateError("Hash is required for a message hash search query.") #

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "hash": self.hash.hex() if self.hash else None,
        })
        return data
