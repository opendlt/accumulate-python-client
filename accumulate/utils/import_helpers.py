# accumulate\utils\import_helpers.py

from asyncio.log import logger
import asyncio
from typing import Optional
from accumulate.utils.url import URL


def get_signer():
    """Dynamically import `Signer` to prevent circular imports."""
    from accumulate.signing.signer import Signer
    return Signer

def is_lite_account_lazy(url: URL) -> bool:
    """Lazy-load `is_lite_account()` to prevent circular imports."""
    from accumulate.utils.validation import is_lite_account
    return is_lite_account(url)


async def query_signer_version(account_url: URL, client: Optional["AccumulateClient"] = None) -> Optional[int]:
    """Fetch the signer version from the network API using AccumulateClient."""

    if client is None:
        from accumulate.api.client import AccumulateClient  
        from accumulate.config import get_accumulate_rpc_url  
        client = AccumulateClient(get_accumulate_rpc_url())

    try:
        logger.info(f" Querying signer version for {account_url}...")

        query_type = "liteIdentity" if is_lite_account_lazy(account_url, client) else "default"

        params = {"scope": str(account_url), "query": {"queryType": query_type}}
        response = await client.json_rpc_request("query", params)

        signer_version = response.get("result", {}).get("account", {}).get("signerVersion", 1)

        logger.info(f" Signer version for {account_url}: {signer_version}")
        return signer_version

    except Exception as e:
        logger.error(f" Failed to fetch signer version for {account_url}: {e}")
        return None  # Return None instead of 1 to indicate an error

    finally:
        await client.close()

