
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
IDENTITY_KEYPAGE_URL = "acc://custom-adi-name-1741948502948.acme/Keybook/1"  # Signer KeyPage


async def update_auth(operation_type: AccountAuthOperationType):
    """Handles different UpdateAccountAuth operations based on user selection."""
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

    ######################### Gather User Input First #########################
    operations = []
    if operation_type == AccountAuthOperationType.ADD_AUTHORITY:
        new_authority = input("Enter the new authority (acc:// format): ").strip()
        operations.append({"type": "addAuthority", "authority": new_authority})
        logger.info(f" Adding Authority: {new_authority}")

    elif operation_type == AccountAuthOperationType.REMOVE_AUTHORITY:
        remove_authority = input("Enter the authority to remove (acc:// format): ").strip()
        operations.append({"type": "removeAuthority", "authority": remove_authority})
        logger.info(f" Removing Authority: {remove_authority}")

    elif operation_type == AccountAuthOperationType.ENABLE:
        enable_authority = input("Enter the authority to enable (acc:// format): ").strip()
        operations.append({"type": "enable", "authority": enable_authority})
        logger.info(f" Enabling Authority: {enable_authority}")

    elif operation_type == AccountAuthOperationType.DISABLE:
        disable_authority = input("Enter the authority to disable (acc:// format): ").strip()
        operations.append({"type": "disable", "authority": disable_authority})
        logger.info(f" Disabling Authority: {disable_authority}")

    else:
        logger.error(" Invalid operation type selected.")
        return

    ######################### Create Transaction Header #########################
    # Generate a manual timestamp (milliseconds) after input collection
    custom_timestamp = 1739950965269936  # Replace with a dynamic value if needed
    tx_header = await TransactionHeader.create(
        principal=ACCOUNT_URL,
        public_key=public_key_32,
        signer=signer,
        timestamp=custom_timestamp
    )
    logger.info(f" Marshaled UpdateAuth Header (HEX): {tx_header.marshal_binary()}")

    ######################### Create Transaction Body #########################
    tx_body = UpdateAccountAuth(
        account_url=URL.parse(ACCOUNT_URL),
        operations=operations
    )

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
    """Interactive menu for selecting UpdateAccountAuth actions."""
    while True:
        print("\n Select an UpdateAuth Operation:")
        print("1 Add an Authority")
        print("2 Remove an Authority")
        print("3 Enable an Authority")
        print("4 Disable an Authority")
        print("0 Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "0":
            print("Exiting...")
            break

        operation_map = {
            "1": AccountAuthOperationType.ADD_AUTHORITY,
            "2": AccountAuthOperationType.REMOVE_AUTHORITY,
            "3": AccountAuthOperationType.ENABLE,
            "4": AccountAuthOperationType.DISABLE,
        }

        if choice in operation_map:
            await update_auth(operation_map[choice])
        else:
            print("Invalid selection. Please choose a valid option.")


if __name__ == "__main__":
    asyncio.run(menu())
