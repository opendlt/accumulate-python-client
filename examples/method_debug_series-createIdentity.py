# examples\method_debug_series-createIdentity.py

#!/usr/bin/env python3
import asyncio
import json
import logging
import hashlib
from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.models.transactions import CreateIdentity, Transaction
from accumulate.utils.hash_functions import LiteAuthorityForKey

#  Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateAddCreditsDebug")

#  Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046" # replace public key
LITE_IDENTITY_URL = "acc://ca7bdd0703147b5e89e1aabc7e165e9c3f8b44ff3708771d"

#  **Sponsor Account (Principal)**
SPONSOR_ACCOUNT = "acc://ca7bdd0703147b5e89e1aabc7e165e9c3f8b44ff3708771d/ACME" 

#  **New Identity Information**
NEW_IDENTITY_URL = "acc://test0001python.acme"
NEW_IDENTITY_KEY_HASH = bytes.fromhex(PUBLIC_KEY_HEX)  # Convert public key to byte format
NEW_IDENTITY_KEYBOOK_URL = "acc://test0001python.acme/Keybook"

#  **Fix Principal Case Sensitivity**
LITE_TOKEN_ACCOUNT = f"{LITE_IDENTITY_URL}/ACME"  #  Changed from 'acme' to 'ACME'

async def process_add_credits():
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    #  Extract keys
    private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
    private_key_32 = private_key_bytes[:32]
    public_key_32 = private_key_bytes[32:]

    logger.info(f" Private Key (32 bytes): {private_key_32.hex()}")
    logger.info(f" Public Key (32 bytes): {public_key_32.hex()}")

    #  Compute Lite Identity URL using Python library (sanity check)
    computed_lite_identity_url = LiteAuthorityForKey(public_key_32, "ED25519")
    logger.info(f" Computed Lite Identity URL: {computed_lite_identity_url}")
    assert computed_lite_identity_url == LITE_IDENTITY_URL, "Mismatch in Lite Identity URL!"

    #  Select signer and determine version
    signer = await Signer.select_signer(URL.parse(LITE_IDENTITY_URL), private_key_32, client)
    logger.info(f" Determined Signer Version: {signer._signer_version}")

    # Generate a manual timestamp (milliseconds)
    custom_timestamp = 1739950965269893  # Replace with your own dynamic value

    tx_header = await TransactionHeader.create(
        principal=SPONSOR_ACCOUNT,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )

######################### Create Transaction Body #########################

    #  Compute new identity URL
    NEW_IDENTITY_URL = URL.parse("acc://test0001python.acme")
    KEY_BOOK_URL = URL.parse("acc://test0001python.acme/Keybook")

    #  Extract public key from signer (to compute key hash)
    signer_public_key = public_key_32  # Use the signer's public key

    #  Create CreateIdentity transaction body (NO need to provide key_hash manually!)
    tx_body = CreateIdentity(NEW_IDENTITY_URL, signer_public_key, KEY_BOOK_URL)

    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled CreateIdentity Body (HEX): {marshaled_body.hex()}")

######################### Create Transaction Strcuture #########################

    #  Create full transaction
    txn = Transaction(header=tx_header, body=tx_body)

#########################

    #  Sign & Submit Transaction
    try:

#        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE)

#        The is a Debug dry run submission - builds envolope without submission
        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE, debug=True)
        #  **Force a manual JSON validation check**
        json_payload = json.dumps(response, indent=4)  # Convert to JSON string (ensures double quotes)
        
        #  Write JSON to file for verification
        with open("debug_rpc_payload.json", "w") as f:
            f.write(json_payload)
        
        #  Print formatted JSON to console for manual validation
        print("\n FINAL JSON Payload (Copy this to JSON Validator):")
        print(json_payload)

        print("\nDEBUG MODE OUTPUT (Not Sent):", response)

    except Exception as e:
        logger.error(f" Transaction Submission Failed: {e}")

if __name__ == "__main__":
    asyncio.run(process_add_credits())
