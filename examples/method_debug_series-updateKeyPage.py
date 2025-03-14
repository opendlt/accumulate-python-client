
#!/usr/bin/env python3
import asyncio
import json
import logging
import hashlib

from httpx import QueryParams
from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.models.transactions import UpdateKeyPage, Transaction
from accumulate.models.key_management import KeySpecParams
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.models.enums import QueryType
from accumulate.models.queries import DefaultQuery, Query, DirectoryQuery

#  Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateUpdateKeyPageDebug")

#  Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046"  # replace public key

#  **Key Page Information**
IDENTITY_URL = "acc://custom-adi-name-1741948502948.acme"
IDENTITY_KEYBOOK_URL = "acc://custom-adi-name-1741948502948.acme/Keybook"
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"

async def process_update_key_page():
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    #  Extract keys
    private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
    private_key_32 = private_key_bytes[:32]
    public_key_32 = private_key_bytes[32:]

    logger.info(f" Private Key (32 bytes): {private_key_32.hex()}")
    logger.info(f" Public Key (32 bytes): {public_key_32.hex()}")

    #  Select signer and determine version
    signer = await Signer.select_signer(URL.parse(IDENTITY_KEYPAGE_URL), private_key_32, client)
    logger.info(f" Determined Signer Version: {signer._signer_version}")

    # Generate a manual timestamp (milliseconds)
    custom_timestamp = 1739950965269940  # Replace with a dynamic value if needed

    tx_header = await TransactionHeader.create(
        principal=IDENTITY_KEYPAGE_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled UpdateKeyPage Header (HEX): {tx_header.marshal_binary()}")

    ######################### Create Transaction Body #########################

    #  Define Key to be added
    new_add_key_hash = KeySpecParams(
        key_hash=hashlib.sha256(
            bytes.fromhex("03419c374c5f2fd41716734ad5a36f25dfc9ec5176dadd075264c6f49ca7fef9")
        ).digest()
    )

    logger.info(f" New Key Hash: {new_add_key_hash.key_hash.hex()}")

    #  Correct format for operations (Fixes KeyError: 'entry')
    operations = [
        {
            "type": "add",
            "entry": {"keyHash": new_add_key_hash.key_hash}  #  Corrected key
        }
    ]

    #  Create UpdateKeyPage transaction body
    tx_body = UpdateKeyPage(
        url=URL.parse(IDENTITY_KEYPAGE_URL),
        operations=operations
    )

    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled UpdateKeyPage Body (HEX): {marshaled_body.hex()}")

    ######################### Create Transaction Structure #########################

    #  Create full transaction
    txn = Transaction(header=tx_header, body=tx_body)

    ######################### Submit Transaction #########################

    #  Sign & Submit Transaction
    try:
        # Debug dry-run submission (no actual broadcast)
        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE, debug=True)

        #  **Force a manual JSON validation check**
        json_payload = json.dumps(response, indent=4)  # Convert to JSON string (ensures double quotes)
        
        #  Write JSON to file for verification
        with open("debug_rpc_payload.json", "w") as f:
            f.write(json_payload)
        
        #  Print formatted JSON to console for manual validation
        print("\n FINAL JSON Payload (Copy this to JSON Validator):")
        print(json_payload)

        print("\n **Manual Validation Steps:**")
        print("1 Open 'debug_rpc_payload.json' and check if it contains double quotes.")
        print("2 Copy and paste the JSON into https://jsonlint.com/ to verify it's valid JSON.")

        print("\nDEBUG MODE OUTPUT (Not Sent):", response)

    except Exception as e:
        logger.error(f" Transaction Submission Failed: {e}")

if __name__ == "__main__":
    asyncio.run(process_update_key_page())
