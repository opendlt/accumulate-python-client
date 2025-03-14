# examples\method_debug_query_simple.py

import asyncio
import logging
from accumulate.api.client import AccumulateClient
from accumulate.models.queries import Query
from accumulate.models.enums import QueryType
from accumulate.models.records import AccountRecord
from accumulate.utils.url import URL
from accumulate.utils.validation import process_signer_url

# Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Accumulate Testnet RPC URL
ACCOUNT_URL = "acc://custom-adi-name-1741948502948.acme/CTACUST"

async def query_account():
    """Query the newly created Lite Token Account to check balance and details."""

    print(f"[INFO] Querying Account: {ACCOUNT_URL}")

    ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

    # Initialize Accumulate Client
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    # Create a query object for the account
    account_query = Query(query_type=QueryType.DEFAULT)

    # Perform the query
    try:
        response = await client.query(ACCOUNT_URL, account_query)

        if isinstance(response, AccountRecord):  # Check if it's an AccountRecord
            print("[SUCCESS] Query successful! Here are the details:\n")
            print(f"[INFO] Account Type: {response.account.get('type', 'Unknown')}")
            print(f"[INFO] Balance: {response.balance} ACME")  # No manual division needed
            print(f"[INFO] Token URL: {response.account.get('tokenUrl', 'N/A')}")
            print(f"[INFO] Account URL: {response.account.get('url', 'N/A')}")
        else:
            print(f"[ERROR] Unexpected record type: {type(response)}")
            print(response.to_dict())

    except Exception as e:
        print(f"[ERROR] Query failed: {e}")

    #  After query is complete, process the signer URL
    account_url = URL.parse(ACCOUNT_URL)
    signer_url = await process_signer_url(account_url, client)
    print(f"[INFO] Processed Signer URL: {signer_url}")

# Run the async function
if __name__ == "__main__":
    asyncio.run(query_account())
