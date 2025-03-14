# \examples\README_exmaples_script.py

import asyncio
import logging
import json
from accumulate.api.client import AccumulateClient
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.utils.address_from import generate_ed25519_keypair
from accumulate.models.queries import Query
from accumulate.models.enums import QueryType
from accumulate.models.base_transactions import TransactionHeader
from accumulate.signing.signer import Signer
from accumulate.models.transactions import AddCredits, Transaction, SendTokens, CreateIdentity
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL

logging.basicConfig(level=logging.INFO)

# Global constants
ACME_TO_CREDITS = 6  # Amount of ACME to convert into credits
SEND_AMOUNT = 2      # Tokens to send from Account 1 to Account 2
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

async def run_full_workflow():
    client = AccumulateClient(ACCUMULATE_RPC_URL)
    query = Query(query_type=QueryType.DEFAULT)
    
    ### 1. Create Lite Token Account 1 ###
    print("\n=== Step 1: Create Lite Token Account 1 ===")
    priv1, pub1 = generate_ed25519_keypair()
    lite_identity_url1 = LiteAuthorityForKey(pub1, "ED25519")
    account1 = f"{lite_identity_url1}/ACME"
    print("Account 1 (Lite Token Account):", account1)
    
    ### 2. Faucet: Fund Account 1 & Query Token Balance ###
    print("\n=== Step 2: Faucet & Query Token Balance ===")
    for i in range(2):
        print(f"Requesting faucet transaction {i+1} for Account 1...")
        await client.faucet(account1)
        await asyncio.sleep(20)  # Wait for transaction settlement

    # Query initial token balance for Account 1
    initial = await client.query(account1, query=query)
    balance_acme = int(initial.balance)
    print("LTA 1 balance after faucet:", initial.balance)

    await asyncio.sleep(5)  # Wait before next step

    ### 3. Purchase Credits for Lite Identity & Query Credit Balance ###
    print("\n=== Step 3: Purchase Credits for Lite Identity ===")

    # First, select the signer
    signer1 = await Signer.select_signer(URL.parse(lite_identity_url1), priv1, client)

    # Now, generate a proper transaction header
    txn_header_credits = await TransactionHeader.create(
        principal=account1,
        public_key=pub1,
        signer=signer1,
    )

    # Build Transaction Body (AddCredits)
    add_credits_txn = AddCredits(
        client=client,
        recipient=URL.parse(lite_identity_url1),
        amount=ACME_TO_CREDITS
    )

    # Initialize oracle value for the transaction
    await add_credits_txn.initialize_oracle()

    # Build the transaction
    txn_credits = Transaction(header=txn_header_credits, body=add_credits_txn)

    # Sign and submit transaction
    response_credits = await signer1.sign_and_submit_transaction(
        client, txn_credits, SignatureType.ED25519
    )

    await asyncio.sleep(25)  # Wait before next step
    # Query credit balance
    credits = await client.query(lite_identity_url1, query=query)
    balance_credits = int(credits.account['creditBalance']) // 100
    print("Lite Identity credit balance:", balance_credits)


    await asyncio.sleep(5)  # Wait before next step
    
    ### 4. Create Lite Token Account 2 & Send Tokens from Account 1 ###
    print("\n=== Step 4: Create Account 2 & Send Tokens ===")

    # Generate keys for Account 2
    priv2, pub2 = generate_ed25519_keypair()
    lite_identity_url2 = LiteAuthorityForKey(pub2, "ED25519")
    account2 = f"{lite_identity_url2}/ACME"
    print("Account 2 (Recipient):", account2)

    await asyncio.sleep(10)  # Optional pause to ensure faucet settled

    # --Build SendTokens Transaction Body--
    send_tx_body = SendTokens()
    send_tx_body.add_recipient(URL.parse(account2), SEND_AMOUNT)  # Add recipient and amount

    # --Build Header--
    txn_header_send = await TransactionHeader.create(
        principal=account1,  # From Account 1
        public_key=pub1,     # Public key of Account 1
        signer=signer1       # Signer associated with Account 1
    )

    # --Combine Header & Body into a Transaction--
    txn_send = Transaction(header=txn_header_send, body=send_tx_body)

    # --Sign and Submit Transaction--
    response_send = await signer1.sign_and_submit_transaction(
        client,
        txn_send,
        SignatureType.ED25519
    )
    await asyncio.sleep(25)  # Wait for transaction to settle

    LTA2_balance = await client.query(account2, query=query)
    balance_acme = int(LTA2_balance.balance)
    print("LTA 2 balance after Send TX:", balance_acme)


    ### 5. Create Accumulate Digital Identity (ADI) ###
    print("\n=== Step 5: Create Accumulate Digital Identity (ADI) ===")

    # Define the new ADI URL and Keybook URL
    new_identity_url = URL.parse("acc://new-identity.acme")
    keybook_url = URL.parse("acc://new-identity.acme/Keybook")

    # Use Account 1's signer and key as the sponsor
    sponsor_account = account1  # This should be your Lite Token Account (acc://<lite>/ACME)

    # --- Build the transaction header ---
    txn_header_adi = await TransactionHeader.create(
        principal=sponsor_account,   # Sponsor account (must have sufficient credits)
        public_key=pub1,             # Public key of the sponsor account
        signer=signer1               # The signer object associated with sponsor
    )

    # --- Build the transaction body (Positional args only, no keyword args) ---
    tx_body_adi = CreateIdentity(
        new_identity_url,    # New ADI's URL
        pub1,               # Public key as raw bytes
        keybook_url          # Keybook URL for ADI's keybook
    )

    # --- Combine Header & Body ---
    txn_adi = Transaction(header=txn_header_adi, body=tx_body_adi)

    # --- Sign and Submit Transaction ---
    response_adi = await signer1.sign_and_submit_transaction(
        client,
        txn_adi,
        SignatureType.ED25519  # Signature type
    )

    await asyncio.sleep(25)  # Wait for transaction to process before querying (adjust as needed)

    # Query back to confirm (although may take more time to appear)
    ADI_Query = await client.query(str(new_identity_url), query=query)
    print("ADI Details:", ADI_Query)

    print("\n=== All exmaple actions completed ===")

asyncio.run(run_full_workflow())
