import asyncio
import logging
import sys
from accumulate.api.client import AccumulateClient
from accumulate.models.records import AccountRecord
from accumulate.models.queries import Query
from accumulate.models.enums import QueryType

#  Enable logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("LiteTokenAccountFaucet")

#  Default Configuration
DEFAULT_LITE_ACCOUNT_URL = "acc://ca7bdd0703147b5e89e1aabc7e165e9c3f8b44ff3708771d/ACME"
DEFAULT_FAUCET_COUNT = 5  # Number of times to request the faucet

async def apply_faucet_to_lta(lite_account_url: str, faucet_count: int):
    """Apply the faucet to a provided Lite Token Account (LTA) multiple times."""
    
    logger.info(f"[INFO] Using Provided Lite Token Account: {lite_account_url}")
    logger.info(f"[INFO] Faucet Requests: {faucet_count} times")

    #  Initialize Accumulate Client
    ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"
    client = AccumulateClient(ACCUMULATE_RPC_URL)

    #  Query account balance before requesting faucet funds
    try:
        query = Query(query_type=QueryType.DEFAULT)  #  Fix: Use DEFAULT instead of ACCOUNT
        balance_response = await client.query(lite_account_url, query=query)
        logger.debug(f" Raw Balance Response Before Processing: {balance_response} (Type: {type(balance_response)})")

        # Ensure response is correctly interpreted
        if isinstance(balance_response, AccountRecord):
            current_balance = balance_response.account.get("balance", "Unknown")  #  Extract from account dict
            current_balance = int(current_balance) / 1e8  #  Convert to ACME units (assuming 8 decimals)
            logger.info(f"[INFO] Current Balance Before Faucet: {current_balance} ACME")
        elif isinstance(balance_response, dict):
            current_balance = balance_response.get("balance", "Unknown")
            logger.info(f"[INFO] Current Balance Before Faucet: {current_balance}")
        else:
            logger.warning(f"[WARN] Unexpected response format: {balance_response} (type: {type(balance_response)})")
    except Exception as e:
        logger.warning(f"[WARN] Could not retrieve account balance before faucet: {e}")

    #  Request ACME tokens from the faucet multiple times with a 1-second delay
    for i in range(faucet_count):
        logger.info(f"[INFO] Requesting faucet transaction ({i + 1}/{faucet_count})...")
        try:
            faucet_response = await client.faucet(lite_account_url)
            logger.info(f"[SUCCESS] Faucet transaction {i + 1} successful!")
            logger.info(f"[TRANSACTION] {faucet_response}")

            #  Query account balance after each faucet call
            try:
                query = Query(query_type=QueryType.DEFAULT)  #  Fix: Use DEFAULT instead of ACCOUNT
                balance_response = await client.query(lite_account_url, query=query)
                logger.debug(f" Raw Balance Response Before Processing: {balance_response} (Type: {type(balance_response)})")

                #  Ensure response is a dictionary
                if isinstance(balance_response, dict):
                    updated_balance = balance_response.get("balance", "Unknown")


                if isinstance(balance_response, AccountRecord):
                    updated_balance = balance_response.account.get("balance", "Unknown")  #  Extract from account dict
                    updated_balance = int(updated_balance) / 1e8  #  Convert to ACME units (assuming 8 decimals)
                    logger.info(f"[INFO] Updated Balance After Faucet ({i + 1}/{faucet_count}): {updated_balance}")
                elif isinstance(balance_response, dict):
                    updated_balance = balance_response.get("balance", "Unknown")
                    logger.info(f"[INFO] Updated Balance After Faucet ({i + 1}/{faucet_count}): {updated_balance}")
                else:
                    logger.warning(f"[WARN] Unexpected response format: {updated_balance} (type: {type(balance_response)})")
            except Exception as e:
                logger.warning(f"[WARN] Could not retrieve account balance after faucet {i + 1}: {e}")

        except Exception as e:
            logger.error(f"[ERROR] Faucet transaction {i + 1} failed: {e}")

        #  Wait 1 second before the next faucet request
        await asyncio.sleep(1)

#  Run the async function with a provided LTA address and faucet count
if __name__ == "__main__":
    if len(sys.argv) < 2:
        lite_token_account = DEFAULT_LITE_ACCOUNT_URL
    else:
        lite_token_account = sys.argv[1]

    faucet_count = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_FAUCET_COUNT

    asyncio.run(apply_faucet_to_lta(lite_token_account, faucet_count))
