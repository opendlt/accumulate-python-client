# C:\Accumulate_Stuff\accumulate-python-client\accumulate\utils\formatting.py 

import hashlib
import base58
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Optional, Union
from decimal import Decimal

# Address Formatting Functions
def format_ac1(hash_bytes: bytes) -> str:
    """Formats an Accumulate AC1 (ed25519) public key hash."""
    return _format_with_prefix(hash_bytes, "AC1")

def format_as1(seed: bytes) -> str:
    """Formats an Accumulate AS1 (ed25519) private key."""
    return _format_with_prefix(seed, "AS1")

def format_ac2(hash_bytes: bytes) -> str:
    """Formats an Accumulate AC2 (ecdsa) public key hash."""
    return _format_with_prefix(hash_bytes, "AC2")

def format_as2(seed: bytes) -> str:
    """Formats an Accumulate AS2 (ecdsa) private key."""
    return _format_with_prefix(seed, "AS2")

def format_ac3(hash_bytes: bytes) -> str:
    """Formats an Accumulate AC3 (rsa) public key hash."""
    return _format_with_prefix(hash_bytes, "AC3")

def format_as3(seed: bytes) -> str:
    """Formats an Accumulate AS3 (rsa) private key."""
    return _format_with_prefix(seed, "AS3")

def format_fa(hash_bytes: bytes) -> str:
    """Formats a Factom FA public key hash."""
    return _format_with_checksum(hash_bytes, b'\x5f\xb1')

def format_fs(seed: bytes) -> str:
    """Formats a Factom Fs private key."""
    return _format_with_checksum(seed, b'\x64\x78')

def format_btc(hash_bytes: bytes) -> str:
    """Formats a Bitcoin P2PKH address prefixed with 'BT'."""
    return "BT" + _format_with_checksum(hash_bytes, b'\x00')

def format_eth(hash_bytes: bytes) -> str:
    """Formats an Ethereum address."""
    # Ensure the hash is exactly 20 bytes long by truncating or padding with zeros
    if len(hash_bytes) > 20:
        hash_bytes = hash_bytes[-20:]  # Take the last 20 bytes
    elif len(hash_bytes) < 20:
        hash_bytes = hash_bytes.rjust(20, b'\x00')  # Pad with leading zeros

    # Convert to hex and prepend the '0x' prefix
    return "0x" + hash_bytes.hex()


def format_mh(hash_bytes: bytes, code: Optional[str] = "sha256") -> str:
    """
    Formats a hash using a specified hashing algorithm and appends a checksum.

    :param hash_bytes: Input data to be hashed.
    :param code: Hashing algorithm (e.g., 'sha256', 'sha512').
    :return: Multihash-formatted string.
    """
    if not hash_bytes:
        raise ValueError("Hash bytes cannot be empty")

    # Hash the input using the specified algorithm
    hashed_data = _hash_with_algorithm(hash_bytes, code)

    # Add checksum
    checksum = _calculate_checksum(b"MH" + hashed_data)
    hashed_data += checksum

    # Encode with base58 and add 'MH' prefix
    return "MH" + base58.b58encode(hashed_data).decode()

# Internal Helpers
def _hash_with_algorithm(data: bytes, algorithm: str) -> bytes:
    """
    Hashes data using the specified algorithm.

    :param data: Data to hash.
    :param algorithm: Hashing algorithm (e.g., 'sha256', 'sha512').
    :return: Hashed bytes.
    """
    algorithms = {
        "sha256": hashes.SHA256,
        "sha512": hashes.SHA512,
    }
    if algorithm not in algorithms:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    digest = hashes.Hash(algorithms[algorithm](), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def _format_with_prefix(hash_bytes: bytes, prefix: str) -> str:
    """Formats the address with a prefix and checksum."""
    if not hash_bytes:
        raise ValueError("Hash bytes cannot be empty")

    address = prefix.encode() + hash_bytes
    checksum = _calculate_checksum(address)
    address += checksum
    return prefix + base58.b58encode(address[len(prefix):]).decode()

def _format_with_checksum(hash_bytes: bytes, prefix: bytes) -> str:
    """Formats the address with a checksum."""
    if not hash_bytes:
        raise ValueError("Hash bytes cannot be empty")

    address = prefix + hash_bytes
    checksum = _calculate_checksum(address)
    address += checksum
    return base58.b58encode(address).decode()

def _calculate_checksum(data: bytes) -> bytes:
    """Calculates a double SHA-256 checksum."""
    checksum = hashlib.sha256(data).digest()
    return hashlib.sha256(checksum).digest()[:4]

# Amount Formatting Functions
def format_amount(amount: int, precision: int) -> str:
    if precision > 1000:
        raise ValueError("Precision is unreasonably large")
    
    if precision == 0:  # Special case for zero precision
        return str(amount)

    amount_str = str(amount).zfill(precision)
    ipart, fpart = amount_str[:-precision], amount_str[-precision:]

    if not ipart:
        ipart = "0"

    return f"{ipart}.{fpart}" if fpart else ipart


def format_big_amount(amount: Union[int, Decimal], precision: int) -> str:
    if precision > 1000:
        raise ValueError("Precision is unreasonably large")

    if precision == 0:  # Special case for zero precision
        return str(amount)

    amount_str = str(amount).zfill(precision)
    ipart, fpart = amount_str[:-precision], amount_str[-precision:]

    if not ipart:
        ipart = "0"

    return f"{ipart}.{fpart}" if fpart else ipart


def validate_precision(precision: int):
    if precision > 1000:
        raise ValueError("Precision is unreasonably large.")

def format_key_page_url(key_book_url: str, page_index: int) -> str:
    if page_index < 0:
        raise ValueError("Page index cannot be negative")
    return f"{key_book_url}/{page_index+1}"

def parse_key_page_url(key_page_url: str) -> tuple:
    parts = key_page_url.rsplit("/", 1)
    if len(parts) != 2:
        raise ValueError("Invalid key page URL")
    key_book_url, page_number = parts
    return key_book_url, int(page_number) - 1


# Example Usage
if __name__ == "__main__":
    # Example hash bytes for testing
    example_hash = bytes.fromhex("abcdef" * 5)

    print("AC1:", format_ac1(example_hash))
    print("AS1:", format_as1(example_hash))
    print("AC2:", format_ac2(example_hash))
    print("BTC:", format_btc(example_hash))
    print("ETH:", format_eth(example_hash))

    # Test Amount Formatting
    print("Amount (int):", format_amount(12345678, 4))
    print("Big Amount (Decimal):", format_big_amount(Decimal("987654321"), 5))
