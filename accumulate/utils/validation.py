# accumulate-python-client\accumulate\utils\validation.py 

import re
from urllib.parse import urlparse
from accumulate.utils.url import URL

class ValidationError(Exception):
    """Raised when validation fails."""

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
    reserved_keywords = {"unknown", "dn", "bvn-"}
    return any(authority.startswith(keyword) for keyword in reserved_keywords)


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

