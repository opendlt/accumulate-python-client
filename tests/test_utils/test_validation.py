# accumulate-python-client\tests\test_utils\test_validation.py

import pytest
from accumulate.utils.validation import (
    validate_accumulate_url,
    is_reserved_url,
    is_valid_adi_url,
    ValidationError,
)
from accumulate.utils.url import (
    URL,
    MissingHostError,
    WrongSchemeError,
    URLParseError
)


# --- Tests for validate_accumulate_url ---
def test_validate_accumulate_url_valid():
    """Test validation of valid Accumulate URLs."""
    valid_urls = [
        URL.parse("acc://example.acme"),
        URL.parse("acc://user.example.acme"),
        # Update to exclude `.com` domain as it raises a ValueError
        URL.parse("acc://example.acme/path"),
        "acc://example.acme",  # String input
        "acc://user.example.acme",  # String input
    ]
    for url in valid_urls:
        if isinstance(url, str):
            url = URL.parse(url)  # Ensure string inputs are parsed into URL objects
        assert validate_accumulate_url(url) is True




def test_validate_accumulate_url_invalid():
    """Test validation of invalid Accumulate URLs."""
    invalid_urls = [
        "",  # Empty string
        "http://example.acme",  # Wrong scheme
        "acc:/example.acme",  # Missing double slashes
        "acc://",  # Missing authority
        "example.com",  # Missing scheme
        "acc://?query=value",  # Missing authority, only query
    ]
    for url in invalid_urls:
        try:
            is_valid = validate_accumulate_url(url)
        except (WrongSchemeError, MissingHostError, ValueError) as e:
            # Expected exceptions for invalid URLs
            print(f"Expected exception caught for {url}: {e}")
            continue
        except Exception as e:
            # Unexpected exception, fail the test
            assert False, f"Unexpected exception for {url}: {e}"
        # If no exception, validate must return False
        assert is_valid is False, f"URL '{url}' should not be valid."


# --- Tests for is_reserved_url ---
def test_is_reserved_url_true():
    """Test URLs that are reserved."""
    reserved_urls = [
        URL.parse("acc://unknown/path"),
        URL.parse("acc://dn/example"),
        URL.parse("acc://bvn-/example"),
        URL.parse("acc://bvn-something/path"),
        "acc://unknown/path",  # String input
    ]
    for url in reserved_urls:
        assert is_reserved_url(url) is True

def test_is_reserved_url_false():
    """Test URLs that are not reserved."""
    non_reserved_urls = [
        URL.parse("acc://example.acme"),
        # Update to exclude `.com` domain as it raises a ValueError
        URL.parse("acc://example.acme/path"),
        URL.parse("acc://bvn.example.acme"),  # Similar to reserved but not matching rules
        "acc://example.acme",  # String input
    ]
    for url in non_reserved_urls:
        if isinstance(url, str):
            url = URL.parse(url)  # Ensure string inputs are parsed into URL objects
        assert is_reserved_url(url) is False


# --- Tests for is_valid_adi_url ---
def test_is_valid_adi_url_valid():
    """Test valid ADI URLs."""
    valid_adi_urls = [
        "example.acme",
        "user-example.acme",
        "account_123.acme",
    ]
    for url in valid_adi_urls:
        assert is_valid_adi_url(url) is True

def test_is_valid_adi_url_invalid():
    """Test invalid ADI URLs."""
    invalid_adi_urls = [
        "",  # Empty string
        "example.com",  # Wrong TLD
        "123.acme",  # Authority cannot be all digits
        "a" * 501,  # Exceeds max length
        "a" * 48 + ".acme",  # Authority exceeds 48 characters
        "000000000000000000000000000000000000000000000000.acme",  # Exactly 48 hex chars
        "example.sub.acme",  # Subdomains not allowed
        "invalid@char.acme",  # Invalid characters
        "acc://example.acme",  # Starts with 'acc://' but should not
    ]
    for url in invalid_adi_urls:
        assert is_valid_adi_url(url) is False

def test_is_valid_adi_url_reserved_disallowed():
    """Test reserved URLs are invalid when allow_reserved=False."""
    reserved_urls = [
        "unknown.acme",
        "dn.acme",
        "bvn-.acme",
    ]
    for url in reserved_urls:
        assert not is_valid_adi_url(url, allow_reserved=False)

def test_is_valid_adi_url_reserved_allowed():
    """Test reserved URLs are valid when allow_reserved=True."""
    reserved_urls = [
        "unknown.acme",
        "dn.acme",
        "bvn-.acme",
    ]
    for url in reserved_urls:
        assert is_valid_adi_url(url, allow_reserved=True)

