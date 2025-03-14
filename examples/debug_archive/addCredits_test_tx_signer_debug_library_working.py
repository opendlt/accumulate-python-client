#!/usr/bin/env python3
# File: \examples\addCredits_test_tx_signer_debug_library_working.py

import asyncio
import json
import logging
import struct
import hashlib
from binascii import hexlify
import time

from accumulate.api.client import AccumulateClient
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL

#  Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateAddCredits")

#  Constants (fixed values)
# Here we use the library enum; ED25519 (value 0x02) is used.
SIGNATURE_TYPE = SignatureType.ED25519  
SIGNER_VERSION = 1
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

#  Accumulate API Client
client = AccumulateClient(ACCUMULATE_RPC_URL)

# --- Helper: Compute Lite Identity URL from Public Key ---
def compute_lite_identity_url(public_key: bytes) -> str:
    pk_hash = hashlib.sha256(public_key).digest()
    logger.debug(f"Public Key SHA256: {pk_hash.hex()}")
    first20 = pk_hash[:20]
    logger.debug(f"First 20 bytes of hash: {first20.hex()}")
    first20_hex = hexlify(first20).decode('utf-8').lower()
    logger.debug(f"First 20 bytes as hex string: {first20_hex}")
    checksum_full = hashlib.sha256(first20_hex.encode('utf-8')).digest()
    logger.debug(f"Full checksum hash: {checksum_full.hex()}")
    checksum = checksum_full[-4:]
    logger.debug(f"Checksum (last 4 bytes): {checksum.hex()}")
    lite_id = first20 + checksum
    lite_identity_url = f"acc://{lite_id.hex()}"
    logger.debug(f"Computed Lite Identity URL: {lite_identity_url}")
    return lite_identity_url

# --- Helper encoding functions (mimicking accumulate's marshalling) ---
def encode_uvarint(value: int) -> bytes:
    buf = []
    while value > 0x7F:
        byte = (value & 0x7F) | 0x80
        buf.append(byte)
        logger.debug(f"encode_uvarint: Appended byte {byte:02x}")
        value >>= 7
    buf.append(value & 0x7F)
    logger.debug(f"encode_uvarint: Final byte {value & 0x7F:02x}")
    result = bytes(buf)
    logger.debug(f"Encoded uvarint: {result.hex()}")
    return result

def encode_compact_int(value: int) -> bytes:
    if value == 0:
        return b'\x00'
    num_bytes = (value.bit_length() + 7) // 8
    result = bytes([num_bytes]) + value.to_bytes(num_bytes, byteorder='big')
    logger.debug(f"Encoded compact int for {value}: {result.hex()}")
    return result

def field_marshal_binary(field: int, data: bytes) -> bytes:
    result = struct.pack("B", field) + data
    logger.debug(f"Field {field} marshaled: {result.hex()}")
    return result

def uvarint_marshal_binary(value: int, field: int = None) -> bytes:
    encoded = encode_uvarint(value)
    if field is not None:
        result = field_marshal_binary(field, encoded)
        logger.debug(f"uvarint_marshal_binary (field {field}): {result.hex()}")
        return result
    else:
        logger.debug(f"uvarint_marshal_binary (no field): {encoded.hex()}")
        return encoded

def string_marshal_binary(value: str, field: int = None) -> bytes:
    value_bytes = value.encode("utf-8")
    data = encode_uvarint(len(value_bytes)) + value_bytes
    if field is not None:
        result = field_marshal_binary(field, data)
        logger.debug(f"string_marshal_binary (field {field}): {result.hex()}")
        return result
    else:
        logger.debug(f"string_marshal_binary (no field): {data.hex()}")
        return data

def bytes_marshal_binary(value: bytes, field: int = None) -> bytes:
    data = encode_uvarint(len(value)) + value
    if field is not None:
        result = field_marshal_binary(field, data)
        logger.debug(f"bytes_marshal_binary (field {field}): {result.hex()}")
        return result
    else:
        logger.debug(f"bytes_marshal_binary (no field): {data.hex()}")
        return data

# --- Transaction Marshalling Functions ---
def marshal_transaction_header(principal: str, initiator: bytes) -> bytes:
    logger.info(" Marshaling Transaction Header")
    principal_bytes = principal.encode("utf-8")
    part1 = encode_uvarint(len(principal_bytes)) + principal_bytes
    field1 = field_marshal_binary(1, part1)
    field2 = field_marshal_binary(2, initiator)
    header_bytes = field1 + field2
    logger.info(f" Marshaled Header Bytes: {header_bytes.hex()}")
    return header_bytes

def marshal_add_credits_body(recipient: str, amount: int, oracle: int) -> bytes:
    logger.info(" Marshaling Transaction Body (AddCredits)")
    oracle_adjusted = oracle * 100
    recipient_bytes = recipient.encode("utf-8")
    field1 = field_marshal_binary(1, b'\x0E')
    field2 = field_marshal_binary(2, encode_uvarint(len(recipient_bytes)) + recipient_bytes)
    field3 = field_marshal_binary(3, encode_compact_int(amount))
    field4 = field_marshal_binary(4, encode_uvarint(oracle_adjusted))
    body_bytes = field1 + field2 + field3 + field4
    logger.info(f" Marshaled Body Bytes HEX: {body_bytes.hex()}")
    logger.info(f" Marshaled Body Bytes: {body_bytes}")
    return body_bytes

def sha256_hash(data: bytes) -> bytes:
    result = hashlib.sha256(data).digest()
    logger.debug(f"SHA256({data.hex()}) = {result.hex()}")
    return result

# --- Main Transaction Process using Library Signer ---
async def process_and_submit_transaction():
    logger.info(" Using Fixed Ed25519 Keypair for Debugging")
    timestamp = int(time.time() * 1e6)
    logger.info(f"Timestamp: {timestamp}")

    # Fixed keypair (hardcoded 64-byte hex string)
    private_key_bytes = bytes.fromhex(
        "add private key here"
    )
    logger.info(f"Fixed Private Key (64 bytes): {private_key_bytes.hex()}")
    private_key_32 = private_key_bytes[:32]
    public_key_32 = private_key_bytes[32:]
    logger.info(f"Using Private Key (32 bytes): {private_key_32.hex()}")
    logger.info(f"Using Public Key (32 bytes): {public_key_32.hex()}")

    # Compute lite identity URL (this remains fixed)
    computed_lite_identity_url = compute_lite_identity_url(public_key_32)
    logger.info(f"Computed Lite Identity URL: {computed_lite_identity_url}")

    lite_identity_url = computed_lite_identity_url
    lite_account_url = f"{lite_identity_url}/acme"
    logger.info(f"Lite Token Account URL: {lite_account_url}")

    # --- Compute Initiator Hash using Library function ---
    lib_initiator_hash = Signer.calculate_metadata_hash(public_key_32, timestamp, lite_identity_url, SIGNER_VERSION, SIGNATURE_TYPE.value)
    logger.info(f"Library Computed Initiator Hash: {lib_initiator_hash.hex()}")

    logger.info(f" Debugging Metadata Hash Inputs")
    logger.info(f"Public Key: {public_key_32.hex()}")
    logger.info(f"Timestamp: {timestamp}")
    logger.info(f"Signer URL: {lite_identity_url}")
    logger.info(f"Signer Version: {SIGNER_VERSION}")
    logger.info(f"Signature Type: {SIGNATURE_TYPE.value}")

    # --- Marshal Transaction Header and Body ---
    # Use the library-computed initiator hash in the header.
    marshaled_header = marshal_transaction_header(lite_account_url, lib_initiator_hash)
    marshaled_body = marshal_add_credits_body(lite_account_url, 6000000, 5000)
    header_hash = sha256_hash(marshaled_header)
    body_hash = sha256_hash(marshaled_body)
    logger.info(f"Header Hash HEX: {header_hash.hex()}")
    logger.info(f"Body Hash HEX: {body_hash.hex()}")
    logger.info(f"Header Hash RAW: {header_hash}")
    logger.info(f"Body Hash RAW: {body_hash}")




    logger.info(f"input_type: Type of header_hash: {type(header_hash)}")
    logger.info(f"input_type: Type of body_hash: {type(body_hash)}")

    # Check the length of the byte objects
    logger.info(f"input_type: Length of header_hash: {len(header_hash)}")
    logger.info(f"input_type: Length of body_hash: {len(body_hash)}")

    final_transaction_hash = sha256_hash(header_hash + body_hash)
    logger.info(f"input_type: Final Transaction Hash HEX: {final_transaction_hash.hex()}")





    
    logger.info(f"Final Transaction Hash HEX: {final_transaction_hash.hex()}")
    logger.info(f"Final Transaction Hash RAW: {final_transaction_hash}")

    # --- Create a library Signer instance and set its keys ---
    signer_url_obj = URL.parse(lite_identity_url)
    lib_signer = Signer(signer_url_obj, signer_version=SIGNER_VERSION)
    lib_signer.set_keys(private_key_32)

    # --- Use the library Signer to sign the final transaction hash ---
    opts = {"signatureType": SIGNATURE_TYPE, "signerVersion": SIGNER_VERSION}
    signature_data = await lib_signer.sign(final_transaction_hash, opts)
    logger.info(f"Library Signature Data: {json.dumps(signature_data, indent=2)}")

    # --- Build the Transaction Envelope using the library signature ---
    envelope = {
        "signatures": [signature_data],
        "transaction": [{
            "header": {
                "principal": lite_account_url,
                # Use the library computed initiator hash here for consistency.
                "initiator": lib_initiator_hash.hex(),
            },
            "body": {
                "type": "addCredits",
                "recipient": lite_account_url,
                "amount": "6000000",
                "oracle": 500000  # Adjusted value (oracle * 100)
            }
        }]
    }

    logger.info("Final Submission Payload:")
    logger.info(json.dumps(envelope, indent=2))

    # --- Submit the Transaction ---
    try:
        response = await client.submit(envelope)
        logger.info(f"Transaction Submitted Successfully! Response: {response}")
    except Exception as e:
        logger.error(f"Transaction Submission Failed: {e}")

if __name__ == "__main__":
    asyncio.run(process_and_submit_transaction())
