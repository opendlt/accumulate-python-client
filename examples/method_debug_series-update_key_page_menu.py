
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
from accumulate.models.transactions import UpdateKeyPage, Transaction
from accumulate.models.key_management import KeySpecParams
from accumulate.models.enums import QueryType
from enum import Enum

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


class KeyPageOperationType(Enum):
    """Operations for key pages."""
    ADD_KEY = 1
    REMOVE_KEY = 2
    UPDATE_KEY = 3
    SET_THRESHOLD = 4
    SET_REJECT_THRESHOLD = 5
    SET_RESPONSE_THRESHOLD = 6
    ADD_DELEGATE = 7
    REMOVE_DELEGATE = 8


async def update_key_page(operation_type):
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
    custom_timestamp = 1739950965269947  # Replace with a dynamic value if needed

    tx_header = await TransactionHeader.create(
        principal=IDENTITY_KEYPAGE_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled UpdateKeyPage Header (HEX): {tx_header.marshal_binary()}")

    ######################### Create Transaction Body #########################

    operations = []

    if operation_type == KeyPageOperationType.ADD_KEY:
        key_input = input("Enter the new key (hex format, 32 bytes): ").strip()
        new_key_hash = KeySpecParams(key_hash=hashlib.sha256(bytes.fromhex(key_input)).digest())

        operations.append({"type": "add", "entry": {"keyHash": new_key_hash.key_hash}})
        logger.info(f" Adding Key Hash: {new_key_hash.key_hash.hex()}")

    elif operation_type == KeyPageOperationType.REMOVE_KEY:
        key_input = input("Enter the key to remove (hex format, 32 bytes): ").strip()
        remove_key_hash = KeySpecParams(key_hash=hashlib.sha256(bytes.fromhex(key_input)).digest())

        operations.append({"type": "remove", "entry": {"keyHash": remove_key_hash.key_hash}})
        logger.info(f" Removing Key Hash: {remove_key_hash.key_hash.hex()}")


    elif operation_type == KeyPageOperationType.UPDATE_KEY:
        old_key = input("Enter the existing key to update (hex format, 32 bytes): ").strip()
        new_key = input("Enter the new key to replace it (hex format, 32 bytes): ").strip()

        old_key_hash = KeySpecParams(key_hash=hashlib.sha256(bytes.fromhex(old_key)).digest())
        new_key_hash = KeySpecParams(key_hash=hashlib.sha256(bytes.fromhex(new_key)).digest())

        operations.append({
            "type": "update",
            "oldEntry": {"keyHash": old_key_hash.key_hash},
            "newEntry": {"keyHash": new_key_hash.key_hash}
        })
        logger.info(f" Updating Key: {old_key_hash.key_hash.hex()} → {new_key_hash.key_hash.hex()}")


    elif operation_type == KeyPageOperationType.SET_THRESHOLD:
        threshold = int(input("Enter the new threshold value: ").strip())
        operations.append({"type": "setThreshold", "threshold": threshold})
        logger.info(f" Setting Threshold to: {threshold}")

    elif operation_type == KeyPageOperationType.SET_REJECT_THRESHOLD:
        reject_threshold = int(input("Enter the new reject threshold value: ").strip())
        operations.append({"type": "setRejectThreshold", "threshold": reject_threshold})
        logger.info(f" Setting Reject Threshold to: {reject_threshold}")

    elif operation_type == KeyPageOperationType.SET_RESPONSE_THRESHOLD:
        response_threshold = int(input("Enter the new response threshold value: ").strip())
        operations.append({"type": "setResponseThreshold", "threshold": response_threshold})
        logger.info(f" Setting Response Threshold to: {response_threshold}")

    elif operation_type == KeyPageOperationType.ADD_DELEGATE:
        delegate_url = input("Enter the Delegate URL to add: ").strip()
        operations.append({"type": "add", "entry": {"delegate": delegate_url}})
        logger.info(f" Adding Delegate: {delegate_url}")

    elif operation_type == KeyPageOperationType.REMOVE_DELEGATE:
        delegate_url = input("Enter the Delegate URL to remove: ").strip()
        operations.append({"type": "remove", "entry": {"delegate": delegate_url}})
        logger.info(f" Removing Delegate: {delegate_url}")

    else:
        logger.error(" Invalid operation type selected.")
        return

    #  Create UpdateKeyPage transaction body
    tx_body = UpdateKeyPage(
        url=URL.parse(IDENTITY_KEYPAGE_URL),
        operations=operations
    )

    #  Log the marshaled body hex
    logger.info(f" Marshaled UpdateKeyPage Body (HEX): {tx_body.marshal().hex()}")

    ######################### Submit Transaction #########################
    txn = Transaction(header=tx_header, body=tx_body)

    try:
        # Debug dry-run submission (no actual broadcast)
        response = await signer.sign_and_submit_transaction(client, txn, SIGNATURE_TYPE, debug=True)

        #  Print formatted JSON for manual validation
        json_payload = json.dumps(response, indent=4)
        print("\n FINAL JSON Payload (Copy this to JSON Validator):")
        print(json_payload)

    except Exception as e:
        logger.error(f" Transaction Submission Failed: {e}")


async def menu():
    """Interactive menu for selecting key page update actions."""
    while True:
        print("\n Select an UpdateKeyPage Operation:")
        print("1 Add a Key")
        print("2 Remove a Key")
        print("3 Update a Key")
        print("4 Set Key Page Threshold")
        print("5 Set Reject Threshold")
        print("6 Set Response Threshold")
        print("7 Add Delegate")
        print("8 Remove Delegate")
        print("0 Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "0":
            print("Exiting...")
            break

        operation_map = {
            "1": KeyPageOperationType.ADD_KEY,
            "2": KeyPageOperationType.REMOVE_KEY,
            "3": KeyPageOperationType.UPDATE_KEY,
            "4": KeyPageOperationType.SET_THRESHOLD,
            "5": KeyPageOperationType.SET_REJECT_THRESHOLD,
            "6": KeyPageOperationType.SET_RESPONSE_THRESHOLD,
            "7": KeyPageOperationType.ADD_DELEGATE,
            "8": KeyPageOperationType.REMOVE_DELEGATE,
        }

        if choice in operation_map:
            await update_key_page(operation_map[choice])
        else:
            print("Invalid selection. Please choose a valid option.")


if __name__ == "__main__":
    asyncio.run(menu())
