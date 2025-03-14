# examples\method_debug_series-issueToken.py

#!/usr/bin/env python3
import asyncio
import json
import logging
import io

from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.models.transactions import IssueTokens, Transaction
from accumulate.models.general import TokenRecipient

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateIssueTokenDebug")

# Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046" # replace public key

# Identity Information
IDENTITY_URL = "acc://custom-adi-name-1741948502948.acme"
IDENTITY_KEYBOOK_URL = "acc://custom-adi-name-1741948502948.acme/Keybook"
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"

# New Token Information for IssueTokens
# Note: In the correct IssueTokens transaction body, the token URL is NOT included.
# Only the recipients list (under the key "to") should be present.
# For testing, we only need to provide a list of recipients.
PRINCIPLE = "acc://custom-adi-name-1741948502948.acme/CUST"
RECIPIENT_URL = "acc://custom-adi-name-1741948502948.acme/CTACUST"
RECIPIENT_AMOUNT = 5270000  # Example amount

async def process_issue_token():
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
    custom_timestamp = 1739950965269923  # Example timestamp

    tx_header = await TransactionHeader.create(
        principal=PRINCIPLE,  # Or your desired principal
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled Header (HEX): {tx_header.marshal_binary().hex()}")

    ######################### Create Transaction Body #########################
    # Create a TokenRecipient instance for testing.
    recipient = TokenRecipient(URL.parse(RECIPIENT_URL), RECIPIENT_AMOUNT)

    # Create the IssueTokens transaction body (which now only contains a list of recipients under the key "to").
    tx_body = IssueTokens([recipient])
    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled IssueTokens Body (HEX): {marshaled_body.hex()}")

    ######################### Create Transaction Structure #########################
    txn = Transaction(header=tx_header, body=tx_body)

    ######################### Sign & Submit Transaction #########################
    try:
        # Debug dry-run submission (no actual broadcast)
#        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE, debug=True)

        # Submit tx to network
        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE)

        json_payload = json.dumps(response, indent=4)
        with open("debug_rpc_payload.json", "w") as f:
            f.write(json_payload)
        print("\n FINAL JSON Payload (Copy to JSON Validator):")
        print(json_payload)
        print("\nDEBUG MODE OUTPUT (Not Sent):", response)
    except Exception as e:
        logger.error(f" Transaction Submission Failed: {e}")

if __name__ == "__main__":
    asyncio.run(process_issue_token())
