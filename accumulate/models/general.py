# accumulate-python-client\accumulate\models\general.py

from dataclasses import dataclass, field
import io
from typing import List, Optional
from accumulate.models.txid_set import TxIdSet
from accumulate.utils.url import URL
from accumulate.utils.encoding import (
    big_number_marshal_binary,
    bytes_marshal_binary,
    field_marshal_binary,
    string_marshal_binary,
    encode_uvarint,
    decode_uvarint,
    unmarshal_bytes,
    unmarshal_string,
)


# General Models

@dataclass
class Object:
    """Generic object with chains and pending transactions."""
    type: str  # Enum for ObjectType
    chains: List["ChainMetadata"] = field(default_factory=list)
    pending: Optional[List["TxIdSet"]] = None  # Pending transactions


@dataclass
class AnchorMetadata:
    """Metadata for an anchor."""
    account: Optional[URL]
    index: int
    source_index: int
    source_block: int
    entry: bytes


@dataclass
class BlockEntry:
    """Represents a single entry in a block."""
    account: Optional[URL]
    chain: str
    index: int


@dataclass
class IndexEntry:
    """Represents an index entry in a chain."""
    source: int
    anchor: Optional[int] = None
    block_index: Optional[int] = None
    block_time: Optional[int] = None  # Unix timestamp
    root_index_index: Optional[int] = None


@dataclass
class AccountAuth:
    """Represents account authorization details."""
    authorities: List["AuthorityEntry"] = field(default_factory=list)


@dataclass
class AuthorityEntry:
    """Represents an entry in the account's authorization list."""
    url: Optional[URL]
    disabled: bool  # True if auth checks are disabled for this authority

@dataclass
class TokenRecipient:
    url: URL
    amount: int

    def __post_init__(self):
        if not self.url:
            raise ValueError("URL cannot be None.")
        if self.amount < 0:
            raise ValueError("Amount must be a non-negative integer.")

    def to_dict(self) -> dict:
        """Convert TokenRecipient to dictionary format for JSON serialization."""
        return {
            "url": str(self.url),  
            "amount": str(self.amount),  
        }

    def __repr__(self) -> str:
        return f"TokenRecipient(url={self.url}, amount={self.amount})"


@dataclass
class CreditRecipient:
    url: Optional[URL]
    amount: int

    def to_dict(self) -> dict:
        """Convert TokenRecipient to dictionary format for JSON serialization."""
        return {
            "url": str(self.url),
            "amount": str(self.amount),  # Convert to string to match Accumulate JSON format
        }


    def marshal(self) -> bytes:
        """Serialize CreditRecipient to bytes."""
        url_data = string_marshal_binary(str(self.url))
        amount_data = encode_uvarint(self.amount)
        return url_data + amount_data

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreditRecipient":
        """Deserialize bytes into CreditRecipient."""
        reader = io.BytesIO(data)

        # Read the URL
        url_length, _ = decode_uvarint(reader.read(2))
        url_str = reader.read(url_length).decode("utf-8")
        url = URL.parse(url_str)

        # Read the amount
        amount, _ = decode_uvarint(reader.read())

        return cls(url, amount)












@dataclass
class FeeSchedule:
    """Represents a fee schedule for the network."""
    create_identity_sliding: List[int]
    create_sub_identity: int
    bare_identity_discount: int


@dataclass
class NetworkLimits:
    """Represents network protocol limits."""
    data_entry_parts: int
    account_authorities: int
    book_pages: int
    page_entries: int
    identity_accounts: int
    pending_major_blocks: int
    events_per_block: int


@dataclass
class NetworkGlobals:
    """Represents network-level global configurations."""
    operator_accept_threshold: float
    validator_accept_threshold: float
    major_block_schedule: str
    anchor_empty_blocks: bool
    fee_schedule: Optional["FeeSchedule"]
    limits: Optional["NetworkLimits"]

