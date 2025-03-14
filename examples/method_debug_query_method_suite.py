
import asyncio
import base64
import logging
import re
from accumulate.api.client import AccumulateClient
from accumulate.models.queries import PublicKeySearchQuery, Query, BlockQuery, PendingQuery, DirectoryQuery, ChainQuery  
from accumulate.models.enums import QueryType
from accumulate.models.signature_types import SignatureType
from accumulate.models.records import (
    AccountRecord, ChainRecord, MessageRecord, RecordRange, UrlRecord, TxIDRecord,
    SignatureSetRecord, KeyRecord, ChainEntryRecord
)
from accumulate.models.options import RangeOptions
from accumulate.utils.address_parse import parse_mh_address

# Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Accumulate Mainnet RPC URL
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

# Example values for testing (Replace these with valid values)
TEST_ACCOUNT = "acc://63f0b1cacc72017f31a5658357b4df7520efe8ea8d744e90/ACME"
DATA_ACCOUNT = "acc://staking.acme/requests"
PENDING_ACCOUNT = "acc://CodeForj.acme/book"
TEST_CHAIN = "acc://FederateThis.acme/tokens"
ANCHOR = "acc://2673d39fa561991c0917594deef412399077f93d143197e5ca3eb4b111f2b6fa@dn.acme/network"
TEST_PUBLIC_KEY = "MHz126PnTKVcdS4bfuRT32U9FRUE8uAKhdTQH2dsJh4d3LntbH6wJAs"
TEST_PUBLIC_KEY_HASH = "54c3147a3839e38a66d7f1a3a876e851441961cfed25321e4a8507a9a1e92571"
PRINCIPLE_ACCOUNT = "acc://HighStakes.acme"
TEST_DELEGATE = "acc://Ethan.acme/book"
BLOCK_VALUE = "32481277"  #  Ensure it's a string (converted later)
TEST_MESSAGE_HASH = "2af659d091d37bd78537a3f3f5654014f845ca28e13ead6ca46ed65db13b98f0"
VALID_DIRECTORY = "acc://codeforj.acme/staking"
VALID_TXID = "acc://a285c24ddc5e1b8aef528a133fc4ed9bff4f58b48134405bd92f66c406a75638@codeforj.acme/staking"

async def test_query(query_type, scope, params=None):
    """Generic function to test different query types."""
    print(f"\n[INFO] Running Query: {query_type.name} for {scope}")

    # Initialize Accumulate Client
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    #  Ensure query_type is passed correctly
    if isinstance(params, BlockQuery):
        params = params.to_dict()  #  Convert to dict before passing

    query = Query(query_type=query_type, params=params or {})

    try:
        response = await client.query(scope, query)

        # Handle different record types dynamically
        if isinstance(response, AccountRecord):
            print(f"[SUCCESS] Account Type: {response.account.get('type', 'Unknown')}")
            print(f"[INFO] Balance: {response.balance} ACME")
            print(f"[INFO] Account URL: {response.account.get('url', 'N/A')}")

        elif isinstance(response, ChainRecord):
            print(f"[SUCCESS] Chain Name: {response.name}, Type: {response.type}, Count: {response.count}")

        elif isinstance(response, ChainEntryRecord):
            print(f"[SUCCESS] Chain Entry: {response.entry}, Index: {response.index}, Account: {response.account}")

        elif isinstance(response, KeyRecord):
            print(f"[SUCCESS] Key Record: Authority: {response.authority}, Signer: {response.signer}, Version: {response.version}")

        elif isinstance(response, SignatureSetRecord):
            print(f"[SUCCESS] Signature Set Record: Signatures Count: {len(response.signatures.records) if response.signatures else 0}")

        elif isinstance(response, MessageRecord):
            print(f"[SUCCESS] Message ID: {response.id}, Status: {response.status}, Signatures: {len(response.signatures.records) if response.signatures else 0}")

        elif isinstance(response, RecordRange):
            print(f"[SUCCESS] Found {len(response.records)} records in range.")

        else:
            print(f"[INFO] Query Response: {response.to_dict()}")

    except Exception as e:
        print(f"[ERROR] Query failed: {e}")

    finally:
        await client.close()


async def interactive_test_runner():
    """Run selected query based on user input."""
    queries = {
        "1": ("DEFAULT (Account)", QueryType.DEFAULT, TEST_ACCOUNT),
        "2": ("CHAIN (Main)", QueryType.CHAIN, TEST_CHAIN, {"name": "main"}),
        "3": ("CHAIN (Signature)", QueryType.CHAIN, TEST_CHAIN, {"name": "signature"}),
        "4": ("CHAIN (Scratch)", QueryType.CHAIN, TEST_CHAIN, {"name": "scratch"}),

        #  No manual Base58 decoding or SignatureType conversion needed
        "5": ("PUBLIC_KEY_SEARCH", QueryType.PUBLIC_KEY_SEARCH, "acc://HighStakes.acme/book", 
            PublicKeySearchQuery(
                public_key="MHz126PnTKVcdS4bfuRT32U9FRUE8uAKhdTQH2dsJh4d3LntbH6wJAs",  #  Base58 key
                signature_type=SignatureType.ED25519  #  Enum value
            ).to_dict()  #  Automatically formats the correct query structure
        ),


        "6": ("PUBLIC_KEY_HASH_SEARCH", QueryType.PUBLIC_KEY_HASH_SEARCH, TEST_ACCOUNT, {
            "queryType": QueryType.PUBLIC_KEY_HASH_SEARCH.to_rpc_format(),  #  Convert to camelCase
            "publicKeyHash": TEST_PUBLIC_KEY_HASH  #  Ensure it's in hex format
        }),

        "7": ("DELEGATE_SEARCH", QueryType.DELEGATE_SEARCH, PRINCIPLE_ACCOUNT, {
            "queryType": "delegateSearch",
            "delegate": TEST_DELEGATE
        }),

        "8": ("MESSAGE_HASH_SEARCH", QueryType.MESSAGE_HASH_SEARCH, VALID_TXID, {"hash": TEST_MESSAGE_HASH}),
        "9": ("CHAIN_ENTRY", QueryType.CHAIN, "acc://ethan.acme", ChainQuery(
            name="main",  #  Explicitly specify "main" chain
            index=5       #  Query a specific chain entry by index
        ).to_dict()),
        "10": ("DIRECTORY Query", QueryType.DIRECTORY, VALID_DIRECTORY, DirectoryQuery(
            range=RangeOptions(start=0, count=10, from_end=False)  #  Ensure range is included
        ).to_dict()),

        "11": ("DATA Query", QueryType.DATA, DATA_ACCOUNT),

        "12": ("PENDING Query", QueryType.PENDING, PENDING_ACCOUNT, PendingQuery(
            range=RangeOptions(start=0, count=10, from_end=False)  #  Ensure range is included
        ).to_dict()),
    }

    while True:
        print("\nSelect a query type to run:")
        for key, (desc, *_) in queries.items():
            print(f"  {key}: {desc}")

        print("  0: Exit")

        choice = input("\nEnter the number of the query to run: ").strip()

        if choice == "0":
            print("Exiting...")
            break

        if choice in queries:
            query_desc, query_type, scope, *params = queries[choice]
            params = params[0] if params else None
            print(f"\n[INFO] Running {query_desc} query...\n")
            await test_query(query_type, scope, params)
        else:
            print("Invalid choice. Please enter a valid number.")


# Run tests interactively
if __name__ == "__main__":
    asyncio.run(interactive_test_runner())

