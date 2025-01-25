# C:\Accumulate_Stuff\accumulate-python-client\accumulate\models\key_management.py

from typing import List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class KeySpec:
    """Represents a key specification with metadata."""
    public_key_hash: bytes
    delegate: Optional[str] = None
    last_used_on: int = 0

    def get_last_used_on(self) -> int:
        """Retrieve the timestamp of the last key usage."""
        return self.last_used_on

    def set_last_used_on(self, timestamp: int) -> None:
        """Set the timestamp of the last key usage."""
        self.last_used_on = timestamp


@dataclass
class KeyPage:
    """Represents a page of keys with threshold signature requirements."""
    accept_threshold: int
    keys: List[KeySpec] = field(default_factory=list)

    def get_m_of_n(self) -> Tuple[int, int]:
        """
        Retrieve the signature requirements for the key page.

        :return: A tuple (m, n) where m is the threshold and n is the total number of keys.
        """
        return self.accept_threshold, len(self.keys)

    def set_threshold(self, m: int) -> None:
        """
        Set the signature threshold for the key page.

        :param m: The required number of signatures.
        :raises ValueError: If the threshold is invalid.
        """
        if m <= 0:
            raise ValueError("Threshold must be greater than 0.")
        if m > len(self.keys):
            raise ValueError(
                f"Cannot require {m} signatures with only {len(self.keys)} keys available."
            )
        self.accept_threshold = m

    def entry_by_key_hash(self, key_hash: bytes) -> Tuple[int, Optional[KeySpec], bool]:
        """
        Find a key entry by its hash.

        :param key_hash: The hash of the key to search for.
        :return: A tuple (index, key_spec, found) where index is the position, key_spec is the found key, and found is a boolean.
        """
        for i, key_spec in enumerate(self.keys):
            if key_spec.public_key_hash == key_hash:
                return i, key_spec, True
        return -1, None, False

    def add_key_spec(self, key_spec: KeySpec) -> None:
        """
        Add a key specification to the key page.

        :param key_spec: The key specification to add.
        """
        self.keys.append(key_spec)
        self.keys.sort(
            key=lambda ks: (ks.public_key_hash, ks.delegate or "")
        )

    def remove_key_spec_at(self, index: int) -> None:
        """
        Remove a key specification at a specific index.

        :param index: The index of the key to remove.
        :raises IndexError: If the index is out of range.
        """
        if not (0 <= index < len(self.keys)):
            raise IndexError("Key index out of range")
        self.keys.pop(index)


@dataclass
class KeySpecParams:
    """Represents the parameters for a key specification."""
    key_hash: bytes
    delegate: Optional[str] = None

    def marshal(self) -> bytes:
        """Serialize the KeySpecParams to bytes."""
        key_hash_length = len(self.key_hash).to_bytes(2, "big")
        delegate_data = self.delegate.encode("utf-8") if self.delegate else b""
        delegate_length = len(delegate_data).to_bytes(2, "big")
        return key_hash_length + self.key_hash + delegate_length + delegate_data

    @classmethod
    def unmarshal(cls, data: bytes) -> "KeySpecParams":
        """Deserialize bytes into a KeySpecParams instance."""
        key_hash_length = int.from_bytes(data[:2], "big")
        key_hash = data[2:2 + key_hash_length]
        delegate_length = int.from_bytes(data[2 + key_hash_length:4 + key_hash_length], "big")
        delegate = (
            data[4 + key_hash_length:4 + key_hash_length + delegate_length].decode("utf-8")
            if delegate_length > 0
            else None
        )
        return cls(key_hash=key_hash, delegate=delegate)

# Key Page Operations
@dataclass
class AddKeyOperation:
    """
    Represents an operation to add a key to a key page.

    :param entry: The key specification to add.
    """
    entry: KeySpec


@dataclass
class RemoveKeyOperation:
    """
    Represents an operation to remove a key from a key page.

    :param entry: The key specification to remove.
    """
    entry: KeySpec


@dataclass
class UpdateKeyOperation:
    """
    Represents an operation to update a key in a key page.

    :param old_entry: The existing key specification to update.
    :param new_entry: The new key specification to replace the old one.
    """
    old_entry: KeySpec
    new_entry: KeySpec


@dataclass
class SetThresholdKeyPageOperation:
    """
    Represents an operation to set the signature threshold for a key page.

    :param threshold: The required number of signatures.
    """
    threshold: int


@dataclass
class SetRejectThresholdKeyPageOperation:
    """
    Represents an operation to set the rejection threshold for a key page.

    :param threshold: The number of signatures required to reject.
    """
    threshold: int


@dataclass
class SetResponseThresholdKeyPageOperation:
    """
    Represents an operation to set the response threshold for a key page.

    :param threshold: The number of signatures required for a response.
    """
    threshold: int


@dataclass
class UpdateAllowedKeyPageOperation:
    """
    Represents an operation to update the allowed or denied transactions for a key page.

    :param allow: List of allowed transaction types.
    :param deny: List of denied transaction types.
    """
    allow: Optional[List[str]] = None
    deny: Optional[List[str]] = None
