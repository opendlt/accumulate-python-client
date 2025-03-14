
# examples\purchase_credits_debug.py

import asyncio
import logging
import time
from accumulate.api.client import AccumulateClient
from accumulate.models.base_transactions import TransactionHeader
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.utils.address_from import generate_ed25519_keypair, from_ed25519_public_key, from_ed25519_private_key 
from accumulate.signing.signer import Signer
from accumulate.signing.builder import Builder
from accumulate.models.transactions import AddCredits, Transaction
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from accumulate.utils.validation import process_signer_url

#  Assign Accumulate RPC URL before usage
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

#  Enable structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AccumulateClient")

# Amount of ACME to convert into credits
ACME_TO_CREDITS = 6


async def purchase_credits_example():
    """Generate a Lite Token Account (LTA), request faucet tokens, and purchase credits."""
    
    logger.info(" Generating Ed25519 Keypair for Lite Account...")

    private_key_64, public_key_32 = generate_ed25519_keypair()

    print(f"Generated Private Key (64 bytes): {private_key_64.hex()}")
    print(f"Generated Public Key (32 bytes): {public_key_32.hex()}")
    print(f"Private Key Length: {len(private_key_64)} bytes")  # Should be 64
    print(f"Public Key Length: {len(public_key_32)} bytes")  # Should be 32

    #  Generate Ed25519 Keypair
    private_key_bytes, public_key_bytes = generate_ed25519_keypair()
    lite_account_url = LiteAuthorityForKey(public_key_bytes, "ED25519")

    #  Extract Lite Identity URL (without `/ACME` at the end)
    lite_identity_url = lite_account_url.rsplit("/", 1)[0]

    logger.info(f" Lite Identity URL: {lite_identity_url}")
    logger.info(f" Lite Token Account: {lite_account_url}")

    #  Initialize Accumulate Client
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    #  Step 1: Request ACME tokens from the faucet
    logger.info(" Requesting faucet transaction to fund Lite Account...")
    try:
        faucet_response = await client.faucet(lite_account_url)
        logger.info(" Faucet transaction successful!")
        logger.info(f" [TRANSACTION] {faucet_response}")
    except Exception as e:
        logger.error(f" Faucet transaction failed: {e}")
        return

    #  Wait for transaction to settle
    await asyncio.sleep(200)

    #  Step 2: Purchase Credits
    logger.info(" Purchasing credits for Lite Identity...")

    #  Create AddCredits with client on the FIRST and ONLY call
    add_credits_txn = AddCredits(
        client=client,  #  Ensure client is passed
        recipient=URL.parse(lite_identity_url),
        amount=ACME_TO_CREDITS
    )

    #  Fetch the oracle price BEFORE proceeding
    await add_credits_txn.initialize_oracle()

    #  Define txn_header before using it
    txn_header = TransactionHeader(
        principal=str(lite_account_url),
        initiator=public_key_bytes
    )

    #  Now create the transaction
    transaction = Transaction(header=txn_header, body=add_credits_txn)

    # Step 1: Select the correct signer (this handles all processing)
    signer = await Signer.select_signer(URL.parse(lite_identity_url), private_key_bytes, client)
    print(f"DEBUG: Public Key - {signer.get_public_key().hex()}")  #  Confirm it's set
    print(f"DEBUG: Private Key - {signer.get_private_key().hex()[:10]}...")  #  Confirm it's set

    # Step 2: Build Signature
    signature = await (
        Builder()
        .set_type(SignatureType.ED25519)
        .set_signer(signer)
        .set_url(URL.parse(lite_account_url))
        .sign(transaction.get_hash())
    )

    #  Construct Envelope with correct formatting
    envelope = {
        "transaction": [transaction.to_dict()],
        "signatures": [signature]
    }

    logger.info("📨 Submitting Add Credits transaction...")
    try:
        response = await client.submit(envelope)
        logger.info(f" Add Credits transaction submitted successfully!")
        logger.info(f" [TRANSACTION HASH] {response}")
    except Exception as e:
        logger.error(f" Add Credits transaction failed: {e}")


#  Ensure proper async execution
if __name__ == "__main__":
    asyncio.run(purchase_credits_example())
