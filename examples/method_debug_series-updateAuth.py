
#!/usr/bin/env python3
import asyncio
import json
import logging

from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.models.transactions import UpdateAccountAuth, Transaction
from accumulate.models.enums import AccountAuthOperationType

#  Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateUpdateAuth")

#  Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046"  # replace public key

#  **Account Information**
ACCOUNT_URL = "acc://custom-adi-name-1741948502948.acme/Data"  # Target account to update
NEW_AUTHORITY = "acc://test0001python.acme/Keybook"  # Authority to add
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"  # Signer KeyPage

async def process_update_auth():
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
    custom_timestamp = 1739950965269933  # Replace with a dynamic value if needed

    tx_header = await TransactionHeader.create(
        principal=ACCOUNT_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled UpdateAuth Header (HEX): {tx_header.marshal_binary()}")

    ######################### Create Transaction Body #########################

    #  Define Operation (ADD_AUTHORITY)
    logger.info(f" Adding Authority: {NEW_AUTHORITY}")

    operations = [
        {
            "type": "addAuthority",  # Operation type as defined in your enum.
            "authority": NEW_AUTHORITY  # Use the key "authority" (a string)
        }
    ]

    #  Create UpdateAccountAuth transaction body
    tx_body = UpdateAccountAuth(
        account_url=URL.parse(ACCOUNT_URL),
        operations=operations
    )

    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled UpdateAuth Body (HEX): {marshaled_body.hex()}")

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

        print("\nDEBUG MODE OUTPUT (Not Sent):", response)

    except Exception as e:
        logger.error(f" Transaction Submission Failed: {e}")

if __name__ == "__main__":
    asyncio.run(process_update_auth())
