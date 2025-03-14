# examples\method_debug_series-sendTokens.py

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
from accumulate.models.transactions import SendTokens, Transaction
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

#  **Fix Principal Case Sensitivity**
LITE_TOKEN_ACCOUNT = f"{LITE_IDENTITY_URL}/ACME"

#  Recipient Account for SendTokens
RECIPIENT_URL = "acc://0408e2065256be92207b41e72f77ef154fc242a4dec2a3e6/ACME"
SEND_AMOUNT = 11  #  Amount to send in ACME

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
    custom_timestamp = 1739950965269892  # Replace with your own dynamic value

    tx_header = await TransactionHeader.create(
        principal=LITE_TOKEN_ACCOUNT,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )



######################### Create Transaction Body #########################

    #  Create SendTokens transaction body
    tx_body = SendTokens()
    tx_body.add_recipient(URL.parse(RECIPIENT_URL), SEND_AMOUNT)  #  Add recipient

    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled SendTokens Body (HEX): {marshaled_body.hex()}")

######################### Create Transaction Strcuture #########################

    #  Create full transaction
    txn = Transaction(header=tx_header, body=tx_body)

#########################

    #  Sign & Submit Transaction
    try:
#        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE)

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
    asyncio.run(process_add_credits())
