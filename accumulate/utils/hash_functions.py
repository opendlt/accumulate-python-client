# accumulate-python-client\accumulate\utils\hash_functions.py

import hashlib
from eth_utils import keccak
from typing import Any
from accumulate.models.signature_types import SignatureType
import base58

# Import EncodingError if it exists, otherwise use ValueError
try:
    from accumulate.utils.encoding import EncodingError
except ImportError:
    class EncodingError(Exception):
        """Exception raised for encoding-related errors"""
        def __init__(self, message="Encoding error occurred"):
            super().__init__(message)

def public_key_hash(public_key: bytes, signature_type: SignatureType) -> bytes:
    """
    Calculate the public key hash based on the signature type
    """
    if signature_type in [
        SignatureType.ED25519,
        SignatureType.LEGACY_ED25519,
        SignatureType.RSA_SHA256,
        SignatureType.ECDSA_SHA256,
    ]:
        return hashlib.sha256(public_key).digest()
    elif signature_type == SignatureType.RCD1:
        return hashlib.sha256(b"RCD" + public_key).digest()
    elif signature_type in [SignatureType.BTC, SignatureType.BTC_LEGACY]:
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(sha256_hash)
        return ripemd160.digest()
    elif signature_type == SignatureType.ETH:
        return keccak(public_key)[-20:]
    else:
        raise ValueError(f"Unsupported signature type for public key hash: {signature_type}")


def compute_hash(obj: Any) -> bytes:
    """
    Compute a SHA-256 hash for an object implementing a `marshal_binary()` method.
    If raw bytes are provided, hash them directly.
    """
    if isinstance(obj, bytes):  #  Allow raw bytes
        return hashlib.sha256(obj).digest()

    if not hasattr(obj, "marshal_binary") or not callable(obj.marshal_binary):
        raise EncodingError("Object must implement a `marshal_binary` method")

    try:
        binary_data = obj.marshal_binary()
    except Exception as e:
        raise EncodingError("Failed to marshal object for hashing") from e

    return hashlib.sha256(binary_data).digest()


def btc_address(public_key: bytes) -> str:
    """
    Generate a BTC address from a public key
    """
    if len(public_key) not in {33, 65}:
        raise ValueError("Invalid public key length for BTC")
    pub_hash = public_key_hash(public_key, SignatureType.BTC)
    versioned_payload = b"\x00" + pub_hash
    checksum = hash_data(hash_data(versioned_payload))[:4]
    return base58.b58encode(versioned_payload + checksum).decode()


def eth_address(public_key: bytes) -> str:
    """
    Generate an ETH address from a public key
    """
    if len(public_key) == 65:  # Uncompressed key
        public_key = public_key[1:]  # Remove the prefix
    if len(public_key) != 64:
        raise ValueError("Invalid public key length for ETH")
    pub_hash = public_key_hash(public_key, SignatureType.ETH)
    return "0x" + pub_hash.hex()


def hash_data(data: bytes) -> bytes:
    """
    Computes the SHA-256 hash of the given data
    """
    if not isinstance(data, bytes):
        raise ValueError("Input must be of type bytes")
    return hashlib.sha256(data).digest()




def LiteAuthorityForKey(pub_key: bytes, signature_type: str) -> str:
    """
    Generate a Lite Token Account (LTA) URL from a public key

    :param pub_key: The public key in bytes
    :param signature_type: The signature type (e.g., "ED25519")
    :return: A valid Lite Token Account (LTA) URL
    """
    key_hash = hashlib.sha256(pub_key).digest()  # SHA-256 Hash
    lite_account = f"acc://{LiteAuthorityForHash(key_hash)}"
    return lite_account

def LiteAuthorityForHash(key_hash: bytes) -> str:
    """
    Generate a Lite Token Account suffix from a key hash

    :param key_hash: The SHA-256 first 20 bytes
    :return: A valid Lite Token Account suffix
    """
    first20 = key_hash[:20]  # Extract the first 20 bytes
    first20_hex = first20.hex()  # Convert first 20 bytes to a hex string
    checksum_full = hashlib.sha256(first20_hex.encode()).digest()  # Hash the hex string
    checksum = checksum_full[-4:]  # Extract the last 4 bytes as checksum
    return f"{(first20 + checksum).hex()}"  # Append checksum and return
