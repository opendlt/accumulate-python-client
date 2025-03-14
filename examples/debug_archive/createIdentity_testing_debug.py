# \examples\createIdentity_testing_debug.py

#!/usr/bin/env python3
import asyncio
import json
import time
import inspect

# Accumulate API dependencies
from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.models.transactions import Transaction
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.config import get_accumulate_rpc_url
from accumulate.models.enums import TransactionType
from accumulate.utils.encoding import encode_uvarint, field_marshal_binary
from accumulate.models.transactions import CreateIdentity
from accumulate.models.key_management import KeySpec

#  Debug: Print the expected arguments for CreateIdentity
print("\n DEBUG: Checking CreateIdentity constructor signature...")
try:
    print(f"CreateIdentity Signature: {inspect.signature(CreateIdentity)}")
except Exception as e:
    print(f" Could not inspect CreateIdentity signature: {e}")

#  Debug: Print the file path where CreateIdentity is defined
print("\n DEBUG: Checking CreateIdentity source file location...")
try:
    print(f"CreateIdentity is defined in: {inspect.getfile(CreateIdentity)}")
except Exception as e:
    print(f" Could not locate CreateIdentity source file: {e}")

#  Debug: Print available attributes
print("\n DEBUG: Checking available attributes in CreateIdentity...")
try:
    print(f"Available attributes: {dir(CreateIdentity)}")
except Exception as e:
    print(f" Could not retrieve CreateIdentity attributes: {e}")

#  Constants
SIGNATURE_TYPE = SignatureType.ED25519
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

#  Accumulate API Client
client = AccumulateClient(ACCUMULATE_RPC_URL)

#  Identity & Key Information
ADI_URL = "acc://custom-adi-name-1741948502948.acme"
KEY_BOOK_URL = "acc://custom-adi-name-1741948502948.acme/book"
KEY_HASH_HEX = "0fd7b06eb78a93c4e6d82295adb69dc4a68c5760bbbf099fc40f2811e1d5f"

#  Hardcoded Private Key
PRIVATE_KEY_HEX = "<< enter 128 charecter private key of signer >> "

async def create_identity():
    timestamp = int(time.time() * 1e6)
    print(f"\n Timestamp: {timestamp}")

    #  Extract private and public keys
    private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
    private_key_32 = private_key_bytes[:32]
    public_key_32 = private_key_bytes[32:]

    print(f" Using Private Key (32 bytes): {private_key_32.hex()}")
    print(f" Using Public Key (32 bytes): {public_key_32.hex()}")

    #  Compute Lite Identity URL using the library method
    lite_identity_url = LiteAuthorityForKey(public_key_32, "ED25519")
    print(f"\n Computed Lite Identity URL: {lite_identity_url}")

    #  Compute the initiator hash using the library's method
    initiator_hash = Signer.calculate_metadata_hash(
        public_key_32, timestamp, lite_identity_url, 1, SIGNATURE_TYPE.value
    )
    print(f" Computed Initiator Hash: {initiator_hash.hex()}")

    #  Create TransactionHeader
    tx_header = TransactionHeader(principal=lite_identity_url, initiator=initiator_hash)

    #  Attempt to Create Transaction Body with key_hash
    print("\n Attempting to create CreateIdentity transaction using key_hash...")
    try:
        tx_body = CreateIdentity(
            url=URL.parse(ADI_URL),
            key_hash=bytes.fromhex(KEY_HASH_HEX),
            key_book_url=URL.parse(KEY_BOOK_URL)
        )
        print(" Successfully created CreateIdentity transaction with key_hash.")
    except Exception as e:
        print(f"\n Failed with key_hash: {e}")
        return

    #  Marshal and Log Encoded Transaction Body
    print("\n Attempting to marshal CreateIdentity transaction body...")
    encoded_tx_body = tx_body.marshal()

    #  Force Print Output if Logs are Failing
    print(f" Encoded CreateIdentity Transaction Body (HEX): {encoded_tx_body.hex()}")

    #  Create the transaction object
    txn = Transaction(header=tx_header, body=tx_body)

    #  Automatically determine signer version using select_signer()
    try:
        signer = await Signer.select_signer(URL.parse(lite_identity_url), private_key_32, client)
        print(f" Determined Signer Version: {signer._signer_version}")
    except Exception as e:
        print(f" Failed to determine signer version: {e}")
        return

    #  Sign & Submit Transaction
    try:
#        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE, debug=True)
#        print("DEBUG MODE OUTPUT (Not Sent):", response)

        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE)
        print(f"\n Transaction Submitted Successfully! Response: {response}")

    except Exception as e:
        print(f"\n Transaction Submission Failed: {e}")

if __name__ == "__main__":
    asyncio.run(create_identity())
