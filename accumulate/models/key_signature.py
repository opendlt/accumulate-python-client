# accumulate-python-client\accumulate\models\key_signature.py

from abc import ABC, abstractmethod
from typing import List, Optional
import hashlib

class KeySignature(ABC):
    """Abstract base class to represent a cryptographic signature."""

    @abstractmethod
    def get_signature(self) -> bytes:
        """Return the signature bytes."""
        pass

    @abstractmethod
    def get_public_key_hash(self) -> bytes:
        """Return the hash of the public key."""
        pass

    @abstractmethod
    def get_public_key(self) -> bytes:
        """Return the public key bytes."""
        pass

    @abstractmethod
    def get_signer_version(self) -> int:
        """Return the version of the signer."""
        pass

    @abstractmethod
    def get_timestamp(self) -> int:
        """Return the timestamp of the signature."""
        pass

class BasicKeySignature(KeySignature):
    def __init__(self, signature: bytes, public_key: bytes, signer_version: int, timestamp: int):
        self._signature = signature
        self._public_key = public_key
        self._signer_version = signer_version
        self._timestamp = timestamp

    def get_signature(self) -> bytes:
        return self._signature

    def get_public_key_hash(self) -> bytes:
        return hashlib.sha256(self._public_key).digest()

    def get_public_key(self) -> bytes:
        return self._public_key

    def get_signer_version(self) -> int:
        return self._signer_version

    def get_timestamp(self) -> int:
        return self._timestamp
