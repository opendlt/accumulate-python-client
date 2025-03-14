
#!/usr/bin/env python3
import asyncio
import json
import logging

from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.models.transactions import BurnTokens, Transaction

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateBurnCustTokenDebug")

# Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046"

# Identity Information
IDENTITY_URL = "acc://custom-adi-name-1741948502948.acme"
IDENTITY_KEYBOOK_URL = "acc://custom-adi-name-1741948502948.acme/Keybook"
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"

# Token Account Information (from which tokens will be burned)
TOKEN_ACCOUNT_URL = "acc://custom-adi-name-1741948502948.acme/CTACUST"
# Provided-readable burn amount (e.g., burn 9 tokens)
PROVIDED_BURN_AMOUNT = 9

async def process_burn_cust_token():
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    # Extract keys
    private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
    private_key_32 = private_key_bytes[:32]
    public_key_32 = private_key_bytes[32:]
    logger.info(f" Private Key (32 bytes): {private_key_32.hex()}")
    logger.info(f" Public Key (32 bytes): {public_key_32.hex()}")

    # Select signer and determine version
    signer = await Signer.select_signer(URL.parse(IDENTITY_KEYPAGE_URL), private_key_32, client)
    logger.info(f" Determined Signer Version: {signer._signer_version}")

    # Generate a manual timestamp (milliseconds)
    custom_timestamp = 1739950965269924

    tx_header = await TransactionHeader.create(
        principal=TOKEN_ACCOUNT_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled Header (HEX): {tx_header.marshal_binary().hex()}")

    ######################### Create Transaction Body #########################
    # Create a BurnTokens instance using the token account URL and provided-readable burn amount.
    burn_tx = BurnTokens(URL.parse(TOKEN_ACCOUNT_URL), PROVIDED_BURN_AMOUNT)
    
    # Dynamically query the blockchain to get the token's precision and update the burn amount.
    await burn_tx.initialize(client)
    
    marshaled_body = burn_tx.marshal()
    logger.info(f" Marshaled BurnTokens Body (HEX): {marshaled_body.hex()}")

    ######################### Create Transaction Structure #########################
    txn = Transaction(header=tx_header, body=burn_tx)

    ######################### Sign & Submit Transaction #########################
    try:
        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE, debug=True)
        json_payload = json.dumps(response, indent=4)
        with open("debug_rpc_payload.json", "w") as f:
            f.write(json_payload)
        print("\n FINAL JSON Payload (Copy to JSON Validator):")
        print(json_payload)
        print("\nDEBUG MODE OUTPUT (Not Sent):", response)
    except Exception as e:
        logger.error(f" Transaction Submission Failed: {e}")

if __name__ == "__main__":
    asyncio.run(process_burn_cust_token())
