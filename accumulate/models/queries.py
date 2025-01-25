# C:\Accumulate_Stuff\accumulate-python-client\accumulate\models\queries.py

from typing import Optional, Union, Dict
from accumulate.models.enums import QueryType
from accumulate.models.options import RangeOptions, ReceiptOptions
from accumulate.api.exceptions import AccumulateError


class Query:
    """Base class for all query types."""

    def __init__(self, query_type: QueryType, params: Optional[dict] = None):
        self.query_type = query_type
        self.params = params or {}

    def is_valid(self) -> bool:
        """Validate the query parameters."""
        if not self.query_type:
            return False
        return True

    def to_dict(self) -> dict:
        """Convert the query to a dictionary."""
        return {"type": self.query_type.name, "params": self.params}


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
        data = super().to_dict()
        data.update({
            "name": self.name,
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
        data = super().to_dict()
        data.update({
            "range": self.range.to_dict() if self.range else None,
        })
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
        data = super().to_dict()
        data.update({
            "range": self.range.to_dict() if self.range else None,
        })
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
        """Validate the block query."""
        if (self.minor and self.major) or (self.minor_range and self.major_range):
            raise AccumulateError("Minor and Major ranges are mutually exclusive.")
        if self.minor and (self.minor_range or self.major_range):
            raise AccumulateError("Minor is mutually exclusive with MinorRange and MajorRange.")
        if self.entry_range and (self.minor_range or self.major_range):
            raise AccumulateError("EntryRange is mutually exclusive with other ranges.")
        if self.entry_range and not (
            self.entry_range.start is not None or self.entry_range.count is not None
        ):
            raise AccumulateError("Invalid EntryRange: Must include `start` or `count`.")


    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "minor": self.minor,
            "major": self.major,
            "minor_range": self.minor_range.to_dict() if self.minor_range else None,
            "major_range": self.major_range.to_dict() if self.major_range else None,
            "entry_range": self.entry_range.to_dict() if self.entry_range else None,
            "omit_empty": self.omit_empty,
        })
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
            raise AccumulateError("Anchor is required for an anchor search query.")
        if self.include_receipt and not (
            self.include_receipt.for_any or self.include_receipt.for_height is not None
        ):
            raise AccumulateError("Invalid ReceiptOptions: Must specify `for_any` or `for_height`.")

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "anchor": self.anchor.hex() if self.anchor else None,
            "include_receipt": self.include_receipt.to_dict() if self.include_receipt else None,
        })
        return data


class PublicKeySearchQuery(Query):
    """Represents a public key search query."""

    def __init__(self, public_key: bytes, signature_type: Optional[str] = None):
        super().__init__(QueryType.PUBLIC_KEY_SEARCH)
        self.public_key = public_key
        self.signature_type = signature_type

    def is_valid(self):
        """Validate the public key search query."""
        if not self.public_key:
            raise AccumulateError("Public key is required for a public key search query.")
        # Additional validation for signature type could be added here if needed.

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "public_key": self.public_key.hex() if self.public_key else None,
            "signature_type": self.signature_type,
        })
        return data


class PublicKeyHashSearchQuery(Query):
    """Represents a public key hash search query."""

    def __init__(self, public_key_hash: bytes):
        super().__init__(QueryType.PUBLIC_KEY_HASH_SEARCH)
        self.public_key_hash = public_key_hash

    def is_valid(self):
        """Validate the public key hash search query."""
        if not self.public_key_hash:
            raise AccumulateError("Public key hash is required for a public key hash search query.")

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "public_key_hash": self.public_key_hash.hex() if self.public_key_hash else None,
        })
        return data


class DelegateSearchQuery(Query):
    """Represents a delegate search query."""

    def __init__(self, delegate: str):
        super().__init__(QueryType.DELEGATE_SEARCH)
        self.delegate = delegate

    def is_valid(self):
        """Validate the delegate search query."""
        if not self.delegate:
            raise AccumulateError("Delegate is required for a delegate search query.")
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
            raise AccumulateError("Hash is required for a message hash search query.")

    def to_dict(self) -> dict:
        data = super().to_dict()
        data.update({
            "hash": self.hash.hex() if self.hash else None,
        })
        return data
