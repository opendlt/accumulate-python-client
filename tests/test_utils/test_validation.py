# accumulate-python-client\tests\test_utils\test_validation.py

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

from accumulate.utils.validation import process_signer_url
from accumulate.utils.url import URL
from accumulate.models.queries import Query
from accumulate.models.enums import QueryType
from accumulate.models.records import AccountRecord


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




@pytest.mark.asyncio
async def test_lite_identity_signer():
    mock_client = AsyncMock()
    mock_client.query.return_value = AccountRecord(account={"type": "liteIdentity"})

    url = URL.parse("acc://lite.identity")
    result = await process_signer_url(url, client=mock_client)

    assert result == {
        "url": str(url),
        "signer_type": "liteIdentity",
        "signer_version": 1
    }


@pytest.mark.asyncio
async def test_lite_token_account_signer():
    mock_client = AsyncMock()
    mock_client.query.return_value = AccountRecord(account={"type": "liteTokenAccount"})

    url = URL.parse("acc://lite.token/ACME")
    result = await process_signer_url(url, client=mock_client)

    assert result == {
        "url": "acc://lite.token",
        "signer_type": "liteTokenAccount",
        "signer_version": 1
    }


@pytest.mark.asyncio
async def test_key_page_signer():
    mock_client = AsyncMock()
    mock_client.query.return_value = AccountRecord(account={"type": "keyPage", "version": 3})

    url = URL.parse("acc://adi.acme/page/1")
    result = await process_signer_url(url, client=mock_client)

    assert result == {
        "url": str(url),
        "signer_type": "keyPage",
        "signer_version": 3
    }


@pytest.mark.asyncio
async def test_adi_signer():
    mock_client = AsyncMock()
    mock_client.query.return_value = AccountRecord(account={"type": "custom.acme"})

    url = URL.parse("acc://custom.acme")
    result = await process_signer_url(url, client=mock_client)

    assert result == {
        "url": str(url),
        "signer_type": "adi",
        "signer_version": 1
    }


@pytest.mark.asyncio
async def test_unknown_account_type():
    mock_client = AsyncMock()
    mock_client.query.return_value = AccountRecord(account={"type": "unknownType"})

    url = URL.parse("acc://weird.account")
    result = await process_signer_url(url, client=mock_client)

    assert result["signer_type"] == "unknown"
    assert result["signer_version"] == 1


@pytest.mark.asyncio
async def test_unexpected_response_format():
    # Not an AccountRecord instance
    mock_client = AsyncMock()
    mock_client.query.return_value = {"not": "account"}

    url = URL.parse("acc://bad.response")
    result = await process_signer_url(url, client=mock_client)

    assert result["signer_type"] == "unknown"
    assert result["signer_version"] == 1


@pytest.mark.asyncio
async def test_query_raises_exception():
    mock_client = AsyncMock()
    mock_client.query.side_effect = Exception("Connection error")

    url = URL.parse("acc://error.url")
    result = await process_signer_url(url, client=mock_client)

    assert result["signer_type"] == "unknown"
    assert result["signer_version"] == 1





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

