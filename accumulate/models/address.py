# accumulate-python-client\accumulate\models\address.py

import base64
import binascii
from typing import Optional, Tuple
import base58
import hashlib

class Address:
    """Abstract base class for addresses."""

    def get_type(self) -> str:
        """Get the type of the address."""
        raise NotImplementedError

    def get_public_key_hash(self) -> Tuple[Optional[bytes], bool]:
        """Get the public key hash."""
        raise NotImplementedError

    def get_public_key(self) -> Tuple[Optional[bytes], bool]:
        """Get the public key."""
        raise NotImplementedError

    def get_private_key(self) -> Tuple[Optional[bytes], bool]:
        """Get the private key."""
        raise NotImplementedError

    def __str__(self) -> str:
        """Return the string representation of the address."""
        raise NotImplementedError


class Unknown(Address):
    """Represents an unknown address."""

    def __init__(self, value: bytes, encoding: str = "hex"):
        self.value = value
        self.encoding = encoding

    def get_type(self) -> str:
        return "Unknown"

    def get_public_key_hash(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def get_public_key(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def get_private_key(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def __str__(self) -> str:
        if self.encoding == "base58":
            return base58.b58encode(self.value).decode()
        return self.value.hex()


class PublicKeyHashAddress(Address):
    """Represents an address based on a public key hash."""

    def __init__(self, signature_type: str, hash_value: bytes):
        self.signature_type = signature_type #
        self.hash_value = hash_value #

    def get_type(self) -> str:
        return self.signature_type

    def get_public_key_hash(self) -> Tuple[Optional[bytes], bool]:
        return self.hash_value, True #
    def get_public_key(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def get_private_key(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def __str__(self) -> str:
        return format_address(self.signature_type, self.hash_value)


class PublicKey(Address):
    """Represents an address based on a public key."""

    def __init__(self, signature_type: str, public_key: bytes):
        self.signature_type = signature_type
        self.public_key = public_key

    def get_type(self) -> str:
        return self.signature_type

    def get_public_key(self) -> Tuple[Optional[bytes], bool]:
        return self.public_key, True

    def get_public_key_hash(self) -> Tuple[Optional[bytes], bool]:
        # Simulate hashing for demonstration
        return hash_public_key(self.public_key, self.signature_type)

    def get_private_key(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def __str__(self) -> str:
        hash_value, valid = self.get_public_key_hash()
        if not valid:
            return "<invalid address>"
        return format_address(self.signature_type, hash_value)


class PrivateKey(PublicKey):
    """Represents an address based on a private key."""

    def __init__(self, signature_type: str, public_key: bytes, private_key: bytes):
        super().__init__(signature_type, public_key)
        self.private_key = private_key

    def get_private_key(self) -> Tuple[Optional[bytes], bool]:
        return self.private_key, True

    def __str__(self) -> str:
        return self.private_key.hex()


class Lite(Address):
    """Represents a lightweight address."""

    def __init__(self, url: str, address_bytes: bytes):
        self.url = url
        self.address_bytes = address_bytes

    def get_type(self) -> str:
        return "Unknown"

    def get_public_key_hash(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def get_public_key(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def get_private_key(self) -> Tuple[Optional[bytes], bool]:
        return None, False

    def __str__(self) -> str:
        return self.url


def format_address(signature_type: str, hash_value: bytes) -> str:
    """Format an address based on its type and hash value."""
    if signature_type in {"ED25519", "LegacyED25519"}:
        return f"AC1-{hash_value.hex()}"
    if signature_type == "RCD1":
        return f"FA-{hash_value.hex()}"
    if signature_type in {"BTC", "BTCLegacy"}:
        return f"BTC-{hash_value.hex()}"
    if signature_type == "ETH":
        return f"ETH-{hash_value.hex()}"
    if signature_type == "EcdsaSha256":
        return f"AC2-{hash_value.hex()}"
    if signature_type == "RsaSha256":
        return f"AC3-{hash_value.hex()}"
    return f"MH-{hash_value.hex()}"


def hash_public_key(public_key: bytes, signature_type: str) -> Tuple[Optional[bytes], bool]:
    """Hash a public key based on its signature type."""
    try:
        if signature_type in {"ED25519", "LegacyED25519"}:
            return hashlib.sha256(public_key).digest(), True
        if signature_type == "BTC":
            return hashlib.sha256(public_key).digest(), True
        return None, False
    except Exception:
        return None, False