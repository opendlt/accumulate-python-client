# accumulate-python-client\accumulate\utils\validation.py 

from asyncio.log import logger
import re
from urllib.parse import urlparse
from accumulate.config import get_accumulate_rpc_url
from accumulate.utils.url import URL
from typing import Optional, TYPE_CHECKING
from accumulate.models.queries import Query, DefaultQuery
from accumulate.models.enums import QueryType
from accumulate.models.records import AccountRecord
import asyncio
import logging
from accumulate.models.errors import ValidationError

if TYPE_CHECKING:
    from accumulate.api.client import AccumulateClient  # Prevents circular imports in type hints

logger = logging.getLogger(__name__)


async def process_signer_url(url: URL, client: Optional["AccumulateClient"] = None) -> dict:
    """
    Determines if a signer is a Lite Identity, Key Page, or ADI and fetches signer version

    Returns:
        dict: {
            "url": str (Processed signer URL),
            "signer_type": str ("liteIdentity", "keyPage", "adi"),
            "signer_version": int (1 for Lite, actual version for Key Page)
        }
    """

    if client is None:
        from accumulate.api.client import AccumulateClient  
        from accumulate.config import get_accumulate_rpc_url  
        client = AccumulateClient(get_accumulate_rpc_url())

    logger.info(f" Querying Accumulate API for signer account type and version: {url}")

    try:
        #  Query the Accumulate API
        query = Query(query_type=QueryType.DEFAULT)
        response = await client.query(str(url), query)

        if not isinstance(response, AccountRecord) or "account" not in response.__dict__:
            logger.warning(f" Unexpected response format for {url}: {response}")
            return {"url": str(url), "signer_type": "unknown", "signer_version": 1}

        #  Extract account type from response
        account_type = response.account.get("type", "unknown").strip().lower()
        logger.info(f" Retrieved Account Type: {account_type} for {url}")

        #  Handle Lite Identity (Always version 1)
        if account_type == "liteidentity":
            return {"url": str(url), "signer_type": "liteIdentity", "signer_version": 1}

        #  Handle Lite Token Accounts (Also version 1)
        elif account_type == "litetokenaccount":
            processed_url = str(url).rsplit("/ACME", 1)[0]
            return {"url": processed_url, "signer_type": "liteTokenAccount", "signer_version": 1}

        #  Handle Key Pages (Extract version from response)
        elif account_type == "keypage":
            signer_version = response.account.get("version", 1)  #  Extract signer version
            logger.info(f" Using Key Page signer. Version: {signer_version}")
            return {"url": str(url), "signer_type": "keyPage", "signer_version": signer_version}

        #  Handle ADI (Assume version 1)
        elif account_type.endswith(".acme"):
            return {"url": str(url), "signer_type": "adi", "signer_version": 1}

        else:
            logger.error(f" Unknown signer type for {url}: {account_type}")
            return {"url": str(url), "signer_type": "unknown", "signer_version": 1}

    except Exception as e:
        logger.error(f" Error processing signer URL for {url}: {e}")
        return {"url": str(url), "signer_type": "unknown", "signer_version": 1}







def validate_accumulate_url(url: URL | str) -> bool:
    """Validate if a URL object or string is a valid Accumulate URL."""
    if isinstance(url, str):
        if not url.startswith("acc://"):
            return False  # Reject URLs that don't start with 'acc://'
        try:
            url = URL.parse(url)
        except ValueError:
            return False
    # Validate the URL object
    if not url.authority:
        return False
    return True

def is_reserved_url(url: URL | str) -> bool:
    """Checks if a URL object or string is reserved."""
    try:
        if isinstance(url, str):
            if not url.startswith("acc://"):
                authority = url.split(".")[0].lower()
            else:
                url = URL.parse(url)
                authority = url.authority.lower()
        else:
            authority = url.authority.lower()
    except ValueError:
        return False

    # Strip the scheme prefix if present
    if authority.startswith("acc://"):
        authority = authority[len("acc://"):]

    reserved_keywords = {"unknown", "dn", "bvn-"}
    return any(authority.startswith(keyword) for keyword in reserved_keywords)




def is_lite_account(account_type: str) -> bool:
    """Returns True if the account type is a Lite Account."""
    return account_type.lower() in ["liteidentity", "litetokenaccount"]


def is_valid_adi_url(url: str, allow_reserved=False) -> bool:
    """Validates an ADI URL according to protocol rules."""
    if not url or len(url) > 500:  # Max length
        return False

    # Check reserved URLs
    if is_reserved_url(url) and not allow_reserved:
        return False

    # Ensure it ends with '.acme'
    tld = ".acme"
    if not url.endswith(tld):
        return False

    authority = url[:-len(tld)]
    if not authority or re.fullmatch(r"\d+", authority):
        # Must not be empty or all digits
        return False

    if len(authority) == 48 and re.fullmatch(r"[a-fA-F0-9]{48}", authority):
        # Must not be exactly 48 hexadecimal characters
        return False

    if "." in authority:
        # Subdomains are not allowed
        return False

    # Must contain only valid characters
    valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    if not set(authority).issubset(valid_chars):
        return False

    return True

