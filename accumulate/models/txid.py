# accumulate-python-client\accumulate\models\txid.py

import json
from typing import TYPE_CHECKING
from accumulate.utils.url import URL, MissingHashError, InvalidHashError

if TYPE_CHECKING:
    from accumulate.models.transactions import Transaction

class TxID:
    """Represents a transaction ID."""

    def __init__(self, url: URL, tx_hash: bytes):
        if not isinstance(url, URL):
            raise ValueError("TxID must be initialized with a URL instance.")
        if not isinstance(tx_hash, bytes) or len(tx_hash) != 32:
            raise ValueError("Transaction hash must be a 32-byte value.")
        self.url = url
        self.tx_hash = tx_hash
        self._str_cache = None

    @staticmethod
    def parse(txid_str: str) -> "TxID":
        """
        Parse a TxID string into a TxID object.
        """
        print(f"Parsing TxID string: {txid_str}")  # Debugging input
        url = URL.parse(txid_str)

        # Validate that '@' is present in the original string
        if "@" not in txid_str:
            raise ValueError(f"Invalid TxID structure: '{txid_str}'. Must contain '@' separating hash and authority.")

        # Validate presence of user_info (TxHash)
        if not url.user_info:
            raise MissingHashError(f"TxID missing hash: {txid_str}")

        try:
            tx_hash = bytes.fromhex(url.user_info)
            if len(tx_hash) != 32:
                raise InvalidHashError(f"Transaction hash must be 32 bytes: {url.user_info}")
        except ValueError as e:
            raise InvalidHashError(f"Invalid transaction hash format: {url.user_info}. Error: {e}")

        # Clean URL (remove TxHash from user_info)
        clean_url = url.with_user_info("")
        return TxID(clean_url, tx_hash)


    def __str__(self) -> str:
        """
        Return the string representation of the TxID.
        """
        if self._str_cache is None:
            # Combine URL and hash as required
            self._str_cache = f"{str(self.url)}@{self.tx_hash.hex()}"
        print(f"String representation of TxID: {self._str_cache}")  # Debugging
        return self._str_cache

    def compare(self, other: "TxID") -> int:
        print(f"Comparing TxIDs: {self} vs {other}")  # Debugging
        if not isinstance(other, TxID):
            raise ValueError("Comparison must be between two TxIDs")
        if self.tx_hash != other.tx_hash:
            return (self.tx_hash > other.tx_hash) - (self.tx_hash < other.tx_hash)
        return (str(self.url) > str(other.url)) - (str(self.url) < str(other.url))  # Updated comparison


    def as_url(self) -> URL:
        """
        Construct a URL representation of the TxID.
        """
        return self.url.with_user_info(self.tx_hash.hex())

    def account(self) -> URL:
        """Get the account URL associated with the TxID."""
        return self.url

    def __eq__(self, other: object) -> bool:
        """Equality operator."""
        return isinstance(other, TxID) and self.tx_hash == other.tx_hash and self.url == other.url

    def __hash__(self) -> int:
        """Hash operator."""
        return hash((str(self.url), self.tx_hash))

    def json(self) -> str:
        """
        Serialize the TxID to a JSON string.
        """
        return json.dumps({"url": str(self.url), "hash": self.tx_hash.hex()})

    @classmethod
    def from_json(cls, json_str: str) -> "TxID":
        """
        Deserialize a JSON string into a TxID instance.
        """
        data = json.loads(json_str)
        url = URL.parse(data["url"])
        tx_hash = bytes.fromhex(data["hash"])
        return cls(url, tx_hash)
