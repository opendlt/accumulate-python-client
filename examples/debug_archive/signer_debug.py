# examples\signer_debug.py

import asyncio
import logging
import struct
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Enable structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AccumulateSignerDebug")

# Constants
SIGNATURE_TYPE = "ed25519"
SIGNER_VERSION = 1

#  Fixed Static Timestamp
STATIC_TIMESTAMP = 1700000000000000 

# Encoding Functions
def encode_uvarint(value: int) -> bytes:
    """Encodes an unsigned integer in Go-compatible UVarint format."""
    buf = []
    while value > 0x7F:
        buf.append((value & 0x7F) | 0x80)  # Extract 7 bits, set MSB
        value >>= 7  # Shift right by 7 bits
    buf.append(value & 0x7F)  # Append last byte without MSB
    return bytes(buf)

#  Accumulate-Specific Key Handling
def extract_private_public_key(concatenated_key: bytes) -> tuple:
    """Extracts the first 32 bytes as the private key and the last 32 bytes as the public key."""
    if len(concatenated_key) != 64:
        raise ValueError(" Expected a 64-byte concatenated private + public key!")
    return concatenated_key[:32], concatenated_key[32:]

def encode_compact_int(value: int) -> bytes:
    """Encodes an integer as a length-prefixed big-endian byte array."""
    if value == 0:
        return b'\x00'
    num_bytes = (value.bit_length() + 7) // 8
    encoded = value.to_bytes(num_bytes, byteorder='big')
    return bytes([num_bytes]) + encoded

def marshal_transaction_header(principal: str, initiator: bytes) -> bytes:
    """Manually serialize the Transaction Header."""
    logger.info(" Marshaling Transaction Header")

    header_bytes = b""
    principal_bytes = principal.encode("utf-8")
    
    # Field 01: Principal
    header_bytes += struct.pack("B", 0x01)  # Field Number
    header_bytes += encode_uvarint(len(principal_bytes))  # Length Prefix
    header_bytes += principal_bytes  # Value

    # Field 02: Initiator (Public Key)
    header_bytes += struct.pack("B", 0x02)  # Field Number
    header_bytes += initiator  # Fixed 32-byte value

    logger.info(f" Marshaled Header Bytes: {header_bytes.hex()}")
    return header_bytes

def marshal_add_credits_body(recipient: str, amount: int, oracle: int) -> bytes:
    """Manually serialize the `AddCredits` transaction body."""
    logger.info(" Marshaling Transaction Body (AddCredits)")

    body_bytes = b""

    # Field 01: Transaction Type (Fixed: 0E for "addCredits")
    body_bytes += struct.pack("B", 0x01) + struct.pack("B", 0x0E)

    # Field 02: Recipient Address
    recipient_bytes = recipient.encode("utf-8")
    body_bytes += struct.pack("B", 0x02)
    body_bytes += encode_uvarint(len(recipient_bytes))
    body_bytes += recipient_bytes

    # Field 03: Amount
    body_bytes += struct.pack("B", 0x03)
    encoded_amount = encode_compact_int(amount)
    body_bytes += encoded_amount

    # Field 04: Oracle Price
    body_bytes += struct.pack("B", 0x04)
    body_bytes += encode_uvarint(oracle)

    logger.info(f" Marshaled Body Bytes: {body_bytes.hex()}")
    return body_bytes

def sha256_hash(data: bytes) -> str:
    """Computes SHA-256 hash and returns as a hex string."""
    return hashlib.sha256(data).hexdigest()


async def debug_transaction_signer():
    """Encode transaction, compute hash, and sign it manually without Signer."""

    logger.info(" Using Fixed Ed25519 Keypair for Debugging...")

    #  Manually define fixed public/private key
    private_key_bytes = bytes.fromhex(" << enter 128 charecter private here >> ")  # Replace with actual private key

    #  Extract 32-byte private key and 32-byte public key
    private_key_32, public_key_32 = extract_private_public_key(private_key_bytes)

    #  Generate Ed25519 private key
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_32)

    #  Ensure derived public key matches
    computed_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    if computed_public_key != public_key_32:
        raise ValueError(" Public key derived from private key does not match stored public key!")

    logger.info(f" Private Key (32 bytes): {private_key_32.hex()}")
    logger.info(f" Public Key (32 bytes): {public_key_32.hex()}")

    lite_identity_url = "acc://bba6cdfa2f3696656462ab0f2baf3b53762f0e2ff6cb85d4"
    lite_account_url = f"{lite_identity_url}/ACME"

    logger.info(f" Lite Identity URL: {lite_identity_url}")
    logger.info(f" Lite Token Account: {lite_account_url}")

    #  Manually Construct Transaction Header
    marshaled_header = b"\x01" + encode_uvarint(len(lite_account_url.encode())) + lite_account_url.encode() + b"\x02" + public_key_32

    #  Manually Construct Transaction Body
    marshaled_body = b"\x01\x0E" + b"\x02" + encode_uvarint(len(lite_account_url.encode())) + lite_account_url.encode()
    marshaled_body += b"\x03" + encode_compact_int(6_000_000)  # Amount
    marshaled_body += b"\x04" + encode_uvarint(5000)  # Oracle

    #  Compute SHA-256 Hashes of Header and Body
    header_hash = hashlib.sha256(marshaled_header).digest()  # Output: raw bytes
    body_hash = hashlib.sha256(marshaled_body).digest()  # Output: raw bytes

    #  Correct way: Concatenate raw bytes before hashing again
    final_transaction_hash = hashlib.sha256(header_hash + body_hash).digest()  # Output: raw bytes
    final_transaction_hash_hex = final_transaction_hash.hex()  # Convert to hex for logging

    #  Log Debug Output
    logger.info(f" Header Hash: {header_hash.hex()}")
    logger.info(f" Body Hash: {body_hash.hex()}")
    logger.info(f" Final Transaction Hash: {final_transaction_hash_hex}")

    #  Use Fixed Timestamp
    timestamp = STATIC_TIMESTAMP

    #  Sign Transaction (Accumulate-Specific Encoding)
    message_hash = hashlib.sha256(final_transaction_hash).digest()
    signature_bytes = private_key.sign(message_hash)

    #  Construct Signed Transaction
    signed_transaction = {
        "type": SIGNATURE_TYPE,  
        "publicKey": public_key_32.hex(),
        "signature": signature_bytes.hex(),
        "signer": lite_identity_url,
        "signerVersion": SIGNER_VERSION,
        "timestamp": timestamp,
        "transactionHash": final_transaction_hash_hex  # Use the hex string here
    }

    logger.info(f" Final Signed Transaction: {signed_transaction}")
    logger.info(" Transaction Successfully Signed!")
        
# Ensure proper async execution
if __name__ == "__main__":
    asyncio.run(debug_transaction_signer())
