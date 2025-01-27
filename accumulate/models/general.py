# accumulate-python-client\accumulate\models\general.py

from dataclasses import dataclass, field
import logging
from typing import List, Optional
from accumulate.models.txid_set import TxIdSet
from accumulate.utils.url import URL
from accumulate.utils.encoding import marshal_bytes, unmarshal_bytes, marshal_string, unmarshal_string, unmarshal_uint, marshal_uint


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
    url: Optional[URL]
    amount: int

    def __post_init__(self):
        if not self.url:
            raise ValueError("URL cannot be None.")
        if self.amount < 0:
            raise ValueError("Amount must be a non-negative integer.")

    def marshal(self) -> bytes:
        url_string = str(self.url).lstrip("acc://")
        url_bytes = f"acc://{url_string}".encode("utf-8")
        url_length = len(url_bytes).to_bytes(2, "big")
        amount_bytes = self.amount.to_bytes(32, "big")
        return url_length + url_bytes + amount_bytes

    @staticmethod
    def unmarshal(data: bytes) -> "TokenRecipient":
        print(f"DEBUG: Unmarshaling data: {data.hex()}")
        if len(data) < 34:
            raise ValueError("Data too short to unmarshal TokenRecipient.")

        url_length = int.from_bytes(data[:2], "big")
        print(f"DEBUG: Extracted URL length: {url_length}")
        if url_length <= 0 or url_length > len(data) - 2:
            raise ValueError("Invalid URL length in data.")

        url_bytes = data[2:2 + url_length]
        url_str = url_bytes.decode("utf-8")
        print(f"DEBUG: Extracted URL string: {url_str}")

        # Ensure the URL does not end with "@"
        if url_str.endswith("@"):
            print("DEBUG: URL string ends with '@'")
            raise ValueError("Invalid URL: URL cannot end with '@'.")

        url = URL.parse(url_str)
        print(f"DEBUG: Parsed URL: {url}")

        if "@" in url.authority and not url.user_info:
            raise ValueError("Invalid URL: Missing user info or authority after '@'.")

        amount = int.from_bytes(data[2 + url_length:], "big")
        print(f"DEBUG: Extracted amount: {amount}")
        if amount < 0:
            raise ValueError("Amount must be a non-negative integer.")

        return TokenRecipient(url, amount)


    def __repr__(self) -> str:
        return f"TokenRecipient(url={self.url}, amount={self.amount})"


@dataclass
class CreditRecipient:
    def __init__(self, url: Optional[URL], amount: int):
        self.url = url
        self.amount = amount

    def marshal(self) -> bytes:
        """Serialize CreditRecipient to bytes."""
        print(f"DEBUG: Marshaling CreditRecipient: URL={self.url}, Amount={self.amount}")

        # Use URL's marshal to ensure "acc://" normalization
        url_data = self.url.marshal()
        print(f"DEBUG: Marshaled URL data: {url_data}")

        amount_data = self.amount.to_bytes(8, "big")  # Serialize the amount
        print(f"DEBUG: Marshaled Amount data: {amount_data}")

        # Combine the serialized URL and amount
        serialized = url_data + amount_data
        print(f"DEBUG: Combined CreditRecipient data before length prefix: {serialized}")

        final_serialized = marshal_bytes(serialized)  # Add length prefix for the recipient data
        print(f"DEBUG: Final marshaled CreditRecipient data with length prefix: {final_serialized}")
        return final_serialized

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreditRecipient":
        """Deserialize bytes into CreditRecipient."""
        print(f"DEBUG: Unmarshaling CreditRecipient from data: {data}")
        recipient_data = unmarshal_bytes(data)  # Extract the length-prefixed recipient data
        print(f"DEBUG: Extracted recipient_data after length prefix: {recipient_data}")

        # Extract and unmarshal URL
        url_data = recipient_data[:-8]  # All bytes except the last 8 (for amount)
        print(f"DEBUG: URL data for unmarshaling: {url_data}")
        url = URL.unmarshal(url_data)

        # Extract amount from the last 8 bytes
        amount_data = recipient_data[-8:]
        print(f"DEBUG: Amount data for unmarshaling: {amount_data}")
        amount = int.from_bytes(amount_data, "big")
        print(f"DEBUG: Extracted Amount: {amount}")

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

