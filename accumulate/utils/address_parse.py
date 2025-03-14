# accumulate-python-client\accumulate\utils\address_parse.py

import hashlib
import base58
from typing import Union
from accumulate.models.errors import ValidationError
from accumulate.models.signatures import PublicKeyHash, PrivateKey, Lite
import re

def parse(address: str) -> Union[PublicKeyHash, PrivateKey, Lite]:
    # Check for short addresses
    if len(address) < 4:
        raise ValidationError("Unknown address format")  

    # Specific address parsers
    if address.startswith("acc://"):
        return parse_lite(address)

    prefix = address[:2]
    try:
        if prefix == "AC":
            return parse_ac_address(address)
        elif prefix == "AS":
            return parse_as_address(address)
        elif prefix == "FA":
            return parse_fa_address(address)
        elif prefix == "Fs":
            return parse_fs_address(address)
        elif prefix == "BT":
            return parse_btc_address(address)
        elif prefix == "0x" and len(address) == 42:  # 20-byte ETH addresses
            return parse_eth_address(address)
        elif prefix == "0x" and len(address) > 42:  # Longer hex gets parsed normally
            return parse_hex_or_base58(address)
        elif prefix == "MH":
            return parse_mh_address(address)
        elif is_wif_key(address):
            return parse_wif(address)
    except ValidationError as e:
        raise e

    #  Allow raw hexadecimal strings (ensure only valid hex characters)
    if re.fullmatch(r"[0-9a-fA-F]+", address) and len(address) >= 8:
        return parse_hex_or_base58(address)

    # Reject clearly invalid formats
    if len(address.strip()) == 0 or not any(c.isalnum() for c in address):
        raise ValidationError("Unknown address format")

    # Reject addresses with unknown prefixes
    known_prefixes = ["AC", "AS", "FA", "Fs", "BT", "0x", "MH", "acc://"]
    if not any(address.startswith(prefix) for prefix in known_prefixes):
        raise ValidationError("Unknown address format")

    # Fallback: Try parsing as hex or Base58
    try:
        return parse_hex_or_base58(address)
    except ValidationError:
        raise ValidationError("Unknown address format")

# Address Type Parsers
def parse_ac_address(address: str) -> PublicKeyHash:
    """Parse an Accumulate public key (AC) address."""
    prefix = address[:3]  # Extract prefix (e.g., "AC1")
    version = address[2:3]  # Extract version (e.g., "1" from "AC1")
    prefix_map = {"1": "AC1", "2": "AC2", "3": "AC3"}
    type_map = {"1": "ED25519", "2": "EcdsaSha256", "3": "RsaSha256"}

    if version not in prefix_map or prefix != prefix_map[version]:
        raise ValidationError(f"Invalid AC address type: {address}")

    # Validate the rest of the address
    hash_bytes = parse_with_prefix(address, 32, prefix_map[version])
    return PublicKeyHash(type_map[version], hash_bytes)


def parse_as_address(address: str) -> PrivateKey:
    """Parse an Accumulate private key (AS) address."""
    prefix = address[:3]  # Extract prefix (e.g., "AS1")
    version = address[2:3]  # Extract version (e.g., "1" from "AS1")
    prefix_map = {"1": "AS1", "2": "AS2", "3": "AS3"}
    type_map = {"1": "ED25519", "2": "EcdsaSha256", "3": "RsaSha256"}

    if version not in prefix_map or prefix != prefix_map[version]:
        raise ValidationError(f"Invalid AS address type: {address}")

    # Validate the rest of the address
    private_key_bytes = parse_with_prefix(address, 32, prefix_map[version])
    return PrivateKey(private_key_bytes, type_map[version])



def parse_fa_address(address: str) -> PublicKeyHash:
    """Parse a Factom public key (FA) address."""
    # Strip the readable prefix before decoding
    if not address.startswith("FA"):  # This condition ensures the prefix validation
        raise ValidationError("Invalid FA address prefix")
    encoded_payload = address[2:]  # Remove the "FA" prefix
    hash_bytes = parse_with_checksum(encoded_payload, 32, b"\x5f\xb1")
    return PublicKeyHash("RCD1", hash_bytes)


def parse_fs_address(address: str) -> PrivateKey:
    """Parse a Factom private key (Fs) address."""
    # Strip the readable prefix before decoding
    if not address.startswith("Fs"):
        raise ValidationError("Invalid Fs address prefix") #
    encoded_payload = address[2:]  # Remove the "Fs" prefix
    private_key_bytes = parse_with_checksum(encoded_payload, 32, b"\x64\x78")
    return PrivateKey(private_key_bytes, "RCD1")



def parse_btc_address(address: str) -> PublicKeyHash:
    """Parse a Bitcoin public key (BT) address."""
    hash_bytes = parse_with_checksum(address[2:], 20, b"\x00")
    return PublicKeyHash("BTC", hash_bytes)


def parse_eth_address(address: str) -> PublicKeyHash:
    """Parse an Ethereum address."""
    if not address.startswith("0x"):
        raise ValidationError("Unknown address format")  # Standardized message

    try:
        hash_bytes = bytes.fromhex(address[2:])
    except ValueError:
        raise ValidationError("Unknown address format")  # Standardized message

    if len(hash_bytes) != 20:
        raise ValidationError("Unknown address format")  # Standardized message #

    return PublicKeyHash("ETH", hash_bytes)




def parse_mh_address(address: str) -> PublicKeyHash:
    """Parse an unknown hash (as a multihash)."""
    if not address.startswith("MH"):
        raise ValidationError("Invalid MH address: bad prefix")
    try:
        decoded = base58.b58decode(address[2:])
    except ValueError: #
        raise ValidationError("Invalid MH address: decoding failed") #
    return PublicKeyHash("Multihash", decoded)


# Helper Functions
def parse_with_prefix(address: str, length: int, prefix: str) -> bytes:
    """Parse an address with a specific prefix and length."""
    if not address.startswith(prefix):
        raise ValidationError(f"Invalid prefix for {prefix}") #
    decoded = base58.b58decode(address[len(prefix):])
    if len(decoded) != length + 4:
        raise ValidationError(f"Invalid length for {prefix} address") #
    checksum = decoded[-4:]
    data = decoded[:-4]
    verify_checksum(data, checksum)
    return data



def parse_with_checksum(address: str, length: int, prefix: bytes) -> bytes:
    """Parse an address with a binary prefix and checksum."""
    decoded = base58.b58decode(address)
    if len(decoded) != len(prefix) + length + 4:
        raise ValidationError("Invalid length")
    if not decoded.startswith(prefix):
        raise ValidationError("Invalid prefix")
    checksum = decoded[-4:]
    data = decoded[len(prefix):-4]
    verify_checksum(decoded[:-4], checksum)
    return data

def parse_hex_or_base58(address: str) -> PublicKeyHash:
    try:
        # Strip "0x" prefix if present before decoding as hex
        hex_address = address[2:] if address.startswith("0x") else address
        decoded = bytes.fromhex(hex_address)

        if len(decoded) < 4:  # Ensure a minimum length for valid hex addresses
            raise ValueError  
        return PublicKeyHash("RawHex", decoded)
    except ValueError:
        pass

    try:
        # Decode as Base58 if not valid hex
        decoded = base58.b58decode(address)
        if len(decoded) < 4:  
            raise ValueError  
        return PublicKeyHash("Base58", decoded)
    except ValueError:
        raise ValidationError("Invalid Hex or Base58 format")






def parse_wif(wif: str) -> PrivateKey:
    """Parse a WIF (Wallet Import Format) encoded key."""
    try:
        decoded = base58.b58decode(wif)
    except ValueError:
        raise ValidationError("Invalid WIF encoding")

    if len(decoded) not in (37, 38):
        raise ValidationError("Invalid WIF length") #
    key = decoded[1:33]
    compressed = len(decoded) == 38
    return PrivateKey(key if not compressed else key[:32], "BTC")


def parse_lite(address: str) -> Lite:
    if not address.startswith("acc://") or len(address) <= len("acc://"):
        raise ValidationError("Unknown address format")
    return Lite(address, b"")


def verify_checksum(data: bytes, checksum: bytes):
    """Verify a double SHA-256 checksum."""
    calculated = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    if calculated != checksum:
        raise ValidationError("Invalid checksum")

def is_wif_key(wif: str) -> bool:
    """
    Check if a string is a valid WIF (Wallet Import Format) key.

    :param wif: The WIF key string.
    :return: True if valid, False otherwise.
    """
    if not wif.startswith(("5", "K", "L")) or len(wif) not in (51, 52):
        return False
    try:
        decoded = base58.b58decode(wif)
        if len(decoded) not in (37, 38):  # 32 bytes private key + 4 bytes checksum (+1 byte for compression flag)
            return False #
        checksum = decoded[-4:]
        expected_checksum = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4]
        return checksum == expected_checksum
    except Exception: #
        return False #
