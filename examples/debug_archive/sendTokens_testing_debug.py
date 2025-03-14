#!/usr/bin/env python3
# \examples\sendTokens_testing_debug.py
import asyncio
import json
import logging
import time

# Accumulate API dependencies
from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.models.transactions import Transaction
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.models.general import TokenRecipient
from accumulate.models.enums import TransactionType
from accumulate.utils.encoding import encode_uvarint, field_marshal_binary
from accumulate.models.transactions import SendTokens

#  Ensure logging is properly configured at the start of execution
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("AccumulateSendTokens")

#  Constants
SIGNATURE_TYPE = SignatureType.ED25519
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

#  Accumulate API Client
client = AccumulateClient(ACCUMULATE_RPC_URL)

#  Sender & Recipient Lite Token Accounts
SENDER_LTA = "Lite Token Account (from)"
RECIPIENT_LTA = "Lite Token Account (to)"

#  Hardcoded Private Key (for sender)
PRIVATE_KEY_HEX = ("<< enter 128 charecter private key here>> ")

async def send_acme_token():
    timestamp = int(time.time() * 1e6)
    logger.info(f"Timestamp: {timestamp}")

    #  Extract private and public keys
    private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
    private_key_32 = private_key_bytes[:32]
    public_key_32 = private_key_bytes[32:]

    logger.info(f"Using Private Key (32 bytes): {private_key_32.hex()}")
    logger.info(f"Using Public Key (32 bytes): {public_key_32.hex()}")

    #  Compute Lite Identity URL using the library method
    lite_identity_url = LiteAuthorityForKey(public_key_32, "ED25519")
    logger.info(f"Computed Lite Identity URL (via library): {lite_identity_url}")

    #  Compute the initiator hash using the library's method
    initiator_hash = Signer.calculate_metadata_hash(
        public_key_32, timestamp, lite_identity_url, 1, SIGNATURE_TYPE.value
    )
    logger.info(f"Library Computed Initiator Hash: {initiator_hash.hex()}")

    #  Create TransactionHeader
    tx_header = TransactionHeader(principal=SENDER_LTA, initiator=initiator_hash)

    #  Prepare SendTokens transaction (1 ACME = 100_000_000 microACME)
    tx_body = SendTokens([TokenRecipient(URL.parse(RECIPIENT_LTA), 100_000_000)])


    #  Marshal and Log Encoded Transaction Body BEFORE Creating Transaction
    logger.debug(f" Attempting to marshal SendTokens transaction body...")
    encoded_tx_body = tx_body.marshal()

    #  Force Print Output if Logs are Failing
    print(f" Encoded SendTokens Transaction Body (HEX): {encoded_tx_body.hex()}")

    logger.debug(f" Forced Debug: Encoded SendTokens Transaction Body (HEX): {encoded_tx_body.hex()}")



    #  Create the transaction object
    txn = Transaction(header=tx_header, body=tx_body)

    #  Automatically determine signer version using select_signer()
    try:
        signer = await Signer.select_signer(URL.parse(lite_identity_url), private_key_32, client)
        logger.info(f" Determined Signer Version: {signer._signer_version}")
    except Exception as e:
        logger.error(f" Failed to determine signer version: {e}")
        return

    #  Sign & Submit Transaction
    try:
        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE)
        logger.info(f" Transaction Submitted Successfully! Response: {response}")
    except Exception as e:
        logger.error(f" Transaction Submission Failed: {e}")


if __name__ == "__main__":
    asyncio.run(send_acme_token())
