# accumulate-python-client\accumulate\models\protocol.py

import hashlib
from typing import Optional, List, Union
from decimal import Decimal
from hashlib import sha256
from accumulate.constants import ACME, UNKNOWN
from accumulate.utils.url import URL
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re
import logging



# Utility Functions
def acme_url() -> URL:
    """Returns the URL for the ACME token."""
    return URL(authority=ACME)


def unknown_url() -> URL:
    """Returns the URL for unknown entities."""
    return URL(authority=UNKNOWN)


def lite_data_address(chain_id: bytes) -> Optional[URL]:
    """Generates a lite data address from a chain ID."""
    if len(chain_id) < 32:
        raise ValueError("chain_id must be 32 bytes long")
    key_str = chain_id.hex()[:32]
    return URL(authority=key_str)


def parse_lite_address(url: URL) -> Optional[bytes]:
    """Parses and validates a lite address."""
    try:
        b = bytes.fromhex(url.authority)
        if len(b) <= 4:
            raise ValueError("Too short")
        byte_value, byte_check = b[:-4], b[-4:]
        checksum = sha256(byte_value).digest()[-4:]
        if checksum != byte_check:
            raise ValueError("Invalid checksum")
        return byte_value
    except Exception as e:
        raise ValueError(f"Error parsing lite address: {e}")
    
def normalize_acc_url(url_str: str) -> str:
    """Ensures a URL starts with the 'acc://' prefix."""
    if not url_str.startswith("acc://"):
        return f"acc://{url_str}"
    return url_str


def lite_token_address(pub_key: bytes, token_url_str: str) -> Optional[URL]:
    """Generates a lite token account URL from a public key and token URL."""
    logger = logging.getLogger(__name__)
    try:
        logger.debug(f"Attempting to generate lite token address for token URL: {token_url_str}")
        print(f"DEBUG: Normalizing token URL: {token_url_str}")

        # Normalize and validate the token URL
        token_url_str = normalize_acc_url(token_url_str)
        print(f"DEBUG: Normalized token URL: {token_url_str}")

        token_url = URL.parse(token_url_str)
        print(f"DEBUG: Parsed token URL: {token_url}")

        # Validate based on token URL type
        print(f"DEBUG: Validating token URL. Authority: {token_url.authority}, Path: {token_url.path}")
        if token_url.path == "" and not re.match(r"^[a-fA-F0-9]{40,64}$", token_url.authority):
            if '.' not in token_url.authority:  # Check if it's a valid ADI
                raise ValueError("Invalid token URL: Missing path or invalid identity format.")

        if token_url.query or token_url.fragment or token_url.user_info:
            raise ValueError("Token URL cannot include query, fragment, or user info.")

        # Generate authority
        key_hash = sha256(pub_key).hexdigest()[:40]
        checksum = sha256(key_hash.encode()).hexdigest()[-8:]
        authority = f"{key_hash}{checksum}"
        print(f"DEBUG: Generated authority: {authority}")

        return URL(authority=authority, path=token_url.path)

    except ValueError as ve:
        logger.error(f"Failed to generate lite token address: {ve}")
        raise ValueError(f"Invalid token URL '{token_url_str}': {ve}") from ve





# Classes
class AccountWithTokens:
    """Interface for accounts that manage tokens."""

    def __init__(self, url: URL, balance: Decimal, token_url: URL):
        self.url = url
        self.balance = balance
        self.token_url = token_url

    def token_balance(self) -> Decimal:
        return self.balance

    def credit_tokens(self, amount: Decimal) -> bool:
        if amount <= 0:
            return False
        self.balance += amount
        return True

    def can_debit_tokens(self, amount: Decimal) -> bool:
        return amount > 0 and self.balance >= amount

    def debit_tokens(self, amount: Decimal) -> bool:
        if not self.can_debit_tokens(amount):
            return False
        self.balance -= amount
        return True

    def get_token_url(self) -> URL:
        return self.token_url


class LiteTokenAccount(AccountWithTokens):
    """Represents a lite token account."""
    pass


class TokenAccount(AccountWithTokens):
    """Represents a standard token account."""
    pass


class TokenIssuer:
    """Represents a token issuer."""

    def __init__(self, issued: Decimal, supply_limit: Optional[Decimal] = None):
        self.issued = issued
        self.supply_limit = supply_limit

    def issue(self, amount: Decimal) -> bool:
        self.issued += amount
        if self.supply_limit is None:
            return True
        return self.issued <= self.supply_limit


class AccountAuthOperation:
    """Base class for account authorization operations."""
    def __init__(self, authority: URL):
        self.authority = authority


class EnableAccountAuthOperation(AccountAuthOperation):
    """Enable authorization for an account."""
    pass


class DisableAccountAuthOperation(AccountAuthOperation):
    """Disable authorization for an account."""
    pass


class AddAccountAuthorityOperation(AccountAuthOperation):
    """Add a new authority to an account."""
    pass


class RemoveAccountAuthorityOperation(AccountAuthOperation):
    """Remove an authority from an account."""
    pass


@dataclass
class Receipt:
    """Represents a receipt with block metadata."""
    local_block: Optional[int] = None
    local_block_time: Optional[str] = None  # ISO 8601 datetime string
    major_block: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert the receipt to a dictionary."""
        return {
            "local_block": self.local_block,
            "local_block_time": self.local_block_time,
            "major_block": self.major_block,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Receipt":
        """Create a receipt from a dictionary."""
        local_block_time = data.get("local_block_time")
        if local_block_time:
            cls._validate_iso8601(local_block_time)

        return cls(
            local_block=data.get("local_block"),
            local_block_time=local_block_time,
            major_block=data.get("major_block"),
        )

    @staticmethod
    def _validate_iso8601(date_str: str):
        """Validate the string is in ISO 8601 format."""
        try:
            datetime.fromisoformat(date_str)
        except ValueError:
            raise ValueError(f"Invalid ISO 8601 datetime: {date_str}")


class AllowedTransactions:
    """Bit mask for allowed transactions."""

    def __init__(self, value: int = 0):
        self.value = value

    def set(self, bit: int) -> None:
        """Set the bit to 1."""
        self.value |= (1 << bit)

    def clear(self, bit: int) -> None:
        """Clear the bit (set to 0)."""
        self.value &= ~(1 << bit)

    def is_set(self, bit: int) -> bool:
        """Check if the bit is set."""
        return (self.value & (1 << bit)) != 0

    def unpack(self) -> List[int]:
        """List all set bits."""
        bits = []
        value = self.value
        bit_index = 0
        while value > 0:
            if value & 1:
                bits.append(bit_index)
            value >>= 1
            bit_index += 1
        return bits

    def get_enum_value(self) -> int:
        """Get the underlying integer value."""
        return self.value

    def set_enum_value(self, value: int) -> None:
        """Set the value from an integer."""
        self.value = value

    def to_json(self) -> str:
        """Serialize the object to JSON."""
        return json.dumps(self.unpack())

    @classmethod
    def from_json(cls, json_str: str) -> "AllowedTransactions":
        """Deserialize from JSON."""
        bits = json.loads(json_str)
        instance = cls()
        for bit in bits:
            instance.set(bit)
        return instance

