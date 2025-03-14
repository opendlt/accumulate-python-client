import asyncio
import logging
from accumulate.api.client import AccumulateClient
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.utils.address_from import generate_ed25519_keypair
from accumulate.config import get_accumulate_rpc_url
from accumulate.models.queries import Query
from accumulate.models.enums import QueryType

#  Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("LiteTokenAccountSetup")

async def create_lite_account_with_faucet():
    """Generate a Lite Token Account (LTA) and request faucet tokens 5 times."""
    
    logger.info("[DEBUG] Generating Keypair for Lite Account...")

    #  Generate Ed25519 Keypair
    private_key_bytes, public_key_bytes = generate_ed25519_keypair()

    #  Generate Lite Token Account URL
    lite_identity_url = LiteAuthorityForKey(public_key_bytes, "ED25519")
    lite_account_url = f"{lite_identity_url}/ACME"

    #  Print Keypair Information
    logger.info(f"[INFO] Public Key (Hex): {public_key_bytes.hex()}")
    logger.info(f"[INFO] Private Key (Hex): {private_key_bytes.hex()}")
    logger.info(f"[INFO] Lite Token Account: {lite_account_url}")


    #  Initialize Accumulate Client
    ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    #  Query account balance before requesting faucet funds
    try:
        query = Query(query_type=QueryType.DEFAULT)  # Use DEFAULT instead of ACCOUNT
        balance_response = await client.query(lite_account_url, query=query)

        current_balance = balance_response.get("balance", "Unknown")
        logger.info(f"[INFO] Current Balance Before Faucet: {current_balance}")
    except Exception as e:
        logger.warning(f"[WARN] Could not retrieve account balance before faucet: {e}")

    #  Request ACME tokens from the faucet 5 times with a 1-second delay
    for i in range(5):
        logger.info(f"[INFO] Requesting faucet transaction ({i + 1}/5)...")
        try:
            faucet_response = await client.faucet(lite_account_url)
            logger.info(f"[SUCCESS] Faucet transaction {i + 1} successful!")
            logger.info(f"[TRANSACTION] {faucet_response}")

            #  Query account balance after each faucet call
            try:
                query = Query(query_type=QueryType.DEFAULT)  # Use DEFAULT instead of ACCOUNT
                balance_response = await client.query(lite_account_url, query=query)

                updated_balance = balance_response.get("balance", "Unknown")
                logger.info(f"[INFO] Updated Balance After Faucet ({i + 1}/5): {updated_balance}")
            except Exception as e:
                logger.warning(f"[WARN] Could not retrieve account balance after faucet {i + 1}: {e}")

        except Exception as e:
            logger.error(f"[ERROR] Faucet transaction {i + 1} failed: {e}")

        #  Wait 1 second before the next faucet request
        await asyncio.sleep(1)

#  Run the async function
if __name__ == "__main__":
    asyncio.run(create_lite_account_with_faucet())
