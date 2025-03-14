import asyncio
import logging
from accumulate.api.client import AccumulateClient

# Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)

# Accumulate Mainnet RPC URL
ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"

# Example values for testing (Replace with actual values)
BLOCK_VALUE = 32481277  #  Ensure it's an integer
MAJOR_VALUE = 13        #  Ensure it's an integer

async def test_block_query(block_type: str, index: int = None, start: int = None, count: int = None):
    """Test function for querying block data."""
    print(f"\n[INFO] Running {block_type.upper()} BLOCK Query...")

    # Initialize Accumulate Client
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    try:
        # Execute block query
        response = await client.query_block(block_type, index=index, start=start, count=count)

        # Print response
        print(f"[SUCCESS] Block Query Response:\n{response}")

    except Exception as e:
        print(f"[ERROR] Block Query failed: {e}")

    finally:
        await client.close()


async def interactive_block_test_runner():
    """Interactive CLI for testing block queries."""
    queries = {
        "1": ("BLOCK Query (Single Minor)", "minor", BLOCK_VALUE, None, None),
        "2": ("BLOCK Query (Minor Range)", "minor", None, 32481277, 10),
        "3": ("BLOCK Query (Single Major)", "major", MAJOR_VALUE, 0, 10),  #  Includes minor_start & minor_count
        "4": ("BLOCK Query (Major Range)", "major", None, 100, 5),
    }

    while True:
        print("\nSelect a block query to run:")
        for key, (desc, *_) in queries.items():
            print(f"  {key}: {desc}")

        print("  0: Exit")

        choice = input("\nEnter the number of the block query to run: ").strip()

        if choice == "0":
            print("Exiting...")
            break

        if choice in queries:
            query_desc, block_type, index, start, count = queries[choice]
            print(f"\n[INFO] Running {query_desc} query...\n")
            await test_block_query(block_type, index, start, count)
        else:
            print("Invalid choice. Please enter a valid number.")


# Run block tests interactively
if __name__ == "__main__":
    asyncio.run(interactive_block_test_runner())
