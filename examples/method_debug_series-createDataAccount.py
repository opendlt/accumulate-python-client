# examples\method_debug_series-createDataAccount.py

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
from accumulate.models.transactions import CreateDataAccount, Transaction
from accumulate.utils.hash_functions import LiteAuthorityForKey

#  Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateCreateDataAccountDebug")

#  Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046" # repalce publi key

#  **New Identity Information**
IDENTITY_URL = "acc://custom-adi-name-1741948502948.acme"
IDENTITY_KEYBOOK_URL = "acc://custom-adi-name-1741948502948.acme/Keybook"
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"

#  **New Token Account Information**
NEW_DATA_ACCOUNT_URL = "acc://custom-adi-name-1741948502948.acme/Data2"

async def process_add_credits():
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
    custom_timestamp = 1739950965269932  # Replace with your own dynamic value

    tx_header = await TransactionHeader.create(
        principal=IDENTITY_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled CreateTokenAccount Header (HEX): {tx_header.marshal_binary()}")


######################### Create Transaction Body #########################

    #  Parse URLs
    data_account_url = URL.parse(NEW_DATA_ACCOUNT_URL)

    #  Create CreateDataAccount transaction body
    tx_body = CreateDataAccount(url=data_account_url)

    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled CreateDataAccount Body (HEX): {marshaled_body.hex()}")

######################### Create Transaction Strcuture #########################

    #  Create full transaction
    txn = Transaction(header=tx_header, body=tx_body)
########################

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
