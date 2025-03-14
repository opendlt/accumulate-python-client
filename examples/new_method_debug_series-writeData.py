# examples\new_method_debug_series-writeData.py

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
from accumulate.models.transactions import WriteData, Transaction
from accumulate.models.data_entries import AccumulateDataEntry, DataEntry, DoubleHashDataEntry 
from accumulate.utils.hash_functions import LiteAuthorityForKey

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("AccumulateWriteDataDebug")

# Constants
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
SIGNATURE_TYPE = SignatureType.ED25519
PRIVATE_KEY_HEX = "<< Enter 128 charecter private key for identinty purchasing credits >>"
PUBLIC_KEY_HEX = "9e6797738d73a7cba1d9c02fabf834f9cfcc873a53776285be96f10f780a0046" # replace public key

# **New Identity Information**
IDENTITY_URL = "acc://custom-adi-name-1741948502948.acme"
IDENTITY_KEYBOOK_URL = "acc://custom-adi-name-1741948502948.acme/Keybook"
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"

# **Data Account Information**
DATA_ACCOUNT_URL = "acc://custom-adi-name-1741948502948.acme/Data"

async def process_write_data():
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
    custom_timestamp = 1739950965269907  # Replace with your own dynamic value

    tx_header = await TransactionHeader.create(
        principal=DATA_ACCOUNT_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled CreateTokenAccount Header (HEX): {tx_header.marshal_binary()}")


######################### Create Transaction Body #########################

    #  Parse URL
    data_account_url = URL.parse(DATA_ACCOUNT_URL)

    #  Define data to write (Example entry)
    data_payload = b"This is a test data entry for Accumulate 1."
    entry = DoubleHashDataEntry(data=[data_payload])

    #  Create WriteData transaction body
    tx_body = WriteData(entry=entry, scratch=False, write_to_state=True)

    marshaled_body = tx_body.marshal()
    logger.info(f" Marshaled WriteData Body (HEX): {marshaled_body.hex()}")

######################### Create Transaction Structure #########################

    #  Create full transaction using hashing-aware logic
    txn = Transaction(header=tx_header, body=tx_body)


    #  Log individual hashes for debugging
    header_hash = hashlib.sha256(txn.header.marshal_binary()).hexdigest()
    body_hash = txn.get_body_hash().hex()
    computed_hash = txn.get_hash().hex()

    logger.info(f" Computed Header Hash: {header_hash}")
    logger.info(f" Computed Body Hash: {body_hash}")
    logger.info(f" Computed Final Transaction Hash: {computed_hash}")

    #  Debugging: Validate against expected values (Replace 'expected_hash' with actual known correct hash)
    expected_hash = "12b1286974abf8a09d7c4cb37257fb3fdba30130ddb0b015f4951cdd07613158"
    if computed_hash == expected_hash:
        logger.info(" Transaction hash matches expected value!")
    else:
        logger.error(" Transaction hash does NOT match expected value!")

    #  Log full transaction hash instead of just the body hash
    computed_hash = txn.get_hash().hex()
    logger.info(f" Computed Transaction Hash: {computed_hash}")


#########################



    #  Sign & Submit Transaction
    try:

        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE)

#        The is a Debug dry run submission - builds envolope without submission
#        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE, debug=True)

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
    asyncio.run(process_write_data())
