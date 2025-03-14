
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
from accumulate.models.transactions import CreateKeyBook, CreateKeyPage, Transaction
from accumulate.models.key_management import KeySpecParams
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.models.enums import QueryType
from accumulate.models.queries import DefaultQuery, Query, DirectoryQuery

#  Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateCreateKeyBookDebug")

#  Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046" # replace public key

#  **New Identity Information**
IDENTITY_URL = "acc://custom-adi-name-1741948502948.acme"
IDENTITY_KEYBOOK_URL = "acc://custom-adi-name-1741948502948.acme/Keybook"
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"

NEW_KEYBOOK_URL = "acc://custom-adi-name-1741948502948.acme/Book2"  # New Key Book
NEW_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Book2/1"  # First Page in New Key Book

async def get_next_keypage_url(client):
    """
    Queries the Key Book to determine the next available Key Page index.
    """
    logger.info(f" Querying Key Book: {IDENTITY_KEYBOOK_URL}")

    try:
        #  Use Default Query to fetch account details
        response = await client.query(IDENTITY_KEYBOOK_URL, Query(query_type=QueryType.DEFAULT))

        #  Ensure response is valid
        if not response or not hasattr(response, "account") or not isinstance(response.account, dict):
            raise ValueError(" Failed to retrieve Key Book account!")

        #  Extract the `type` field correctly
        account_type = response.account.get("type")
        if account_type != "keyBook":
            raise ValueError(f" Retrieved account is not a Key Book! Found: {account_type}")

        #  Extract Key Page count
        key_page_count = response.account.get("pageCount")
        if key_page_count is None:
            raise ValueError(" Failed to retrieve Key Page count from Key Book!")

        next_keypage_index = key_page_count + 1

        #  Construct the new Key Page URL
        next_keypage_url = f"{IDENTITY_KEYBOOK_URL}/{next_keypage_index}"
        logger.info(f" Next Key Page URL: {next_keypage_url}")

        return next_keypage_url

    except Exception as e:
        logger.error(f" Query Failed: {e}")
        raise


async def process_create_key_book():
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    #  Extract keys
    private_key_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
    private_key_32 = private_key_bytes[:32]
    public_key_32 = private_key_bytes[32:]

    logger.info(f" Private Key (32 bytes): {private_key_32.hex()}")
    logger.info(f" Public Key (32 bytes): {public_key_32.hex()}")

    #  Determine the next Key Page URL
    next_keypage_url = await get_next_keypage_url(client)

    #  Select signer and determine version
    signer = await Signer.select_signer(URL.parse(IDENTITY_KEYPAGE_URL), private_key_32, client)
    logger.info(f" Determined Signer Version: {signer._signer_version}")

    # Generate a manual timestamp (milliseconds)
    custom_timestamp = 1739950965269911  # Replace with your own dynamic value

    tx_header = await TransactionHeader.create(
        principal=IDENTITY_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled CreateTokenAccount Header (HEX): {tx_header.marshal_binary()}")

######################### Create Transaction Body #########################

    #  Define Key Book Parameters
    new_keybook_public_key_hash = hashlib.sha256(bytes.fromhex("03419c374c5f2fd41716734ad5a36f25dfc9ec5176dadd075264c6f49ca7fef9")).digest()
    authorities = [URL.parse(f"{IDENTITY_URL}/Keybook")]  #  This ensures a valid path


    logger.info(f" Creating New Key Book: {NEW_KEYBOOK_URL}")

    #  Create CreateKeyBook transaction body
    tx_body = CreateKeyBook(
        url=URL.parse(NEW_KEYBOOK_URL),
        public_key_hash=new_keybook_public_key_hash,
    )

    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled CreateKeyBook Body (HEX): {marshaled_body.hex()}")

    #  Create full transaction for Key Book
    txn = Transaction(header=tx_header, body=tx_body)

######################### Create Transaction Strcuture #########################

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
    asyncio.run(process_create_key_book())