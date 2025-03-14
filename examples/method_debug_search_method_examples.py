
import asyncio
import logging
from accumulate.api.client import AccumulateClient
from accumulate.models.search import AnchorSearchQuery, PublicKeySearchQuery, DelegateSearchQuery
from accumulate.models.enums import QueryType

# Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Accumulate Mainnet RPC URL
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

# Example values for testing (Replace these with valid values)
TEST_ACCOUNT = "acc://custom-adi-name-1741948502948.acme"
TEST_ANCHOR = "7a6b36e10fc8e858f7fe224ee5524d1ee29b9a3962f26634fddfbad178fc4890@dn.acme/anchors"
TEST_PUBLIC_KEY = "MHz125KoKeVVdFRw98AECVEaH2NPMgfTovZL6gJvM7asGnL1f9k7Dfb"
TEST_DELEGATE = "acc://billyBob.acme/book" # Use accoutn with a delegate authority entry in it's key book 
PUBLIC_KEY_TYPE = "ed25519"  # Change based on supported key types (e.g., btc, eth)


async def test_search(search_query):
    """Generic function to test different search types using JSON-RPC."""
    print(f"\n[INFO] Running Search: {search_query.query_type.name} for {search_query.value}")

    # Initialize Accumulate Client
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    try:
        #  Corrected to use JSON-RPC request
        response = await client.search(
            TEST_ACCOUNT,
            search_query.query_type.to_rpc_format(),
            search_query.value,
            search_query.extra_params
        )

        print(f"[SUCCESS] Search Response:\n{response}")

    except Exception as e:
        print(f"[ERROR] Search failed: {e}")

    finally:
        await client.close()


async def interactive_search_test_runner():
    """Interactive CLI for testing search queries."""
    searches = {
        "1": ("ANCHOR_SEARCH", AnchorSearchQuery(TEST_ANCHOR, include_receipt=True)),
        "2": ("PUBLIC_KEY_SEARCH", PublicKeySearchQuery(TEST_PUBLIC_KEY, key_type=PUBLIC_KEY_TYPE)),
        "3": ("DELEGATE_SEARCH", DelegateSearchQuery(TEST_DELEGATE)),
    }

    while True:
        print("\nSelect a search query to run:")
        for key, (desc, _) in searches.items():
            print(f"  {key}: {desc}")

        print("  0: Exit")

        choice = input("\nEnter the number of the search query to run: ").strip()

        if choice == "0":
            print("Exiting...")
            break

        if choice in searches:
            search_desc, search_query = searches[choice]
            print(f"\n[INFO] Running {search_desc} query...\n")
            await test_search(search_query)
        else:
            print("Invalid choice. Please enter a valid number.")


# Run search tests interactively
if __name__ == "__main__":
    asyncio.run(interactive_search_test_runner())
