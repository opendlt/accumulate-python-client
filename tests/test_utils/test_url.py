# accumulate-python-client\tests\test_utils\test_url.py

import pytest
from accumulate.utils.url import URL, InvalidHashError, MissingHostError, WrongSchemeError, URLParseError, invalid_hash, missing_hash, MissingHashError

# --- Updated Tests for URL Parsing ---
def test_url_parse_lite_identity():
    """Test parsing a lite identity URL."""
    url = URL.parse("acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56")
    # Expect the authority to retain the "acc://" prefix
    assert url.authority == "acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"
    assert url.path == ""
    assert str(url) == "acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"

def test_url_parse_lite_token_account():
    """Test parsing a lite token account URL."""
    url = URL.parse("acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56/ACME")
    assert url.authority == "acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"
    assert url.path == "/ACME"
    assert str(url) == "acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56/ACME"

def test_url_parse_accumulate_identity():
    """Test parsing an Accumulate Identity URL."""
    url = URL.parse("acc://DefiDevs.acme")
    assert url.authority == "acc://DefiDevs.acme"
    assert url.path == ""
    assert str(url) == "acc://DefiDevs.acme"

def test_url_parse_accumulate_key_book():
    """Test parsing an Accumulate key book URL."""
    url = URL.parse("acc://DefiDevs.acme/book")
    assert url.authority == "acc://DefiDevs.acme"
    assert url.path == "/book"
    assert str(url) == "acc://DefiDevs.acme/book"

def test_url_parse_accumulate_key_page():
    """Test parsing an Accumulate key page URL."""
    url = URL.parse("acc://DefiDevs.acme/book/1")
    assert url.authority == "acc://DefiDevs.acme"
    assert url.path == "/book/1"
    assert str(url) == "acc://DefiDevs.acme/book/1"

# --- Tests for URL Parsing ---
def test_url_parse_missing_scheme():
    """Test parsing a URL without the 'acc://' scheme."""
    url_str = "0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"
    try:
        URL.parse(url_str)
    except WrongSchemeError as e:
        print(f"Expected exception caught for {url_str}: {e}")
        return
    except Exception as e:
        print(f"Unexpected exception: {e}")
    assert False, "Expected WrongSchemeError was not raised."

def test_url_parse_missing_authority():
    """Test parsing a URL with missing authority."""
    url_str = "acc:///path"
    with pytest.raises(ValueError, match="Invalid URL: Authority cannot be empty"):
        URL.parse(url_str)

def test_url_parse_empty_string():
    """Test parsing an empty URL string."""
    url_str = ""
    try:
        URL.parse(url_str)
    except ValueError as e:
        print(f"Expected exception caught: {e}")
        return
    except Exception as e:
        print(f"Unexpected exception: {e}")
    assert False, "Expected ValueError was not raised."

def test_url_parse_invalid_scheme():
    """Test parsing a URL with an invalid scheme."""
    url_str = "http://DefiDevs.acme"
    try:
        URL.parse(url_str)
    except WrongSchemeError as e:
        print(f"Expected exception caught: {e}")
        return
    except Exception as e:
        print(f"Unexpected exception: {e}")
    assert False, "Expected WrongSchemeError was not raised."

# --- Updated Tests for URL String Representation ---
def test_url_to_string():
    """Test converting a URL object back into its string representation."""
    url = URL(user_info="user", authority="DefiDevs.acme", path="/path", query="query=value", fragment="fragment")
    # Expect the string to include the user info and "acc://" prefix on the authority.
    assert str(url) == "user@acc://DefiDevs.acme/path?query=value#fragment"

# --- Tests for URL Equality and Comparison ---
def test_url_equality():
    """Test equality of two URLs."""
    url1 = URL.parse("acc://DefiDevs.acme/book")
    url2 = URL.parse("acc://DefiDevs.acme/book")
    assert url1 == url2

def test_url_inequality():
    """Test inequality of two URLs."""
    url1 = URL.parse("acc://DefiDevs.acme/book1")
    url2 = URL.parse("acc://DefiDevs.acme/book2")
    assert url1 != url2

def test_url_comparison():
    """Test lexicographic comparison of URLs."""
    url1 = URL.parse("acc://DefiDevs.acme/a")
    url2 = URL.parse("acc://DefiDevs.acme/b")
    assert url1 < url2
    assert url2 > url1
    assert not (url1 > url2)

# --- Tests for URL Copy ---
def test_url_copy():
    """Test copying a URL with overrides."""
    url = URL.parse("acc://DefiDevs.acme/book")
    copied_url = url.with_path("/new_book").with_query("query=value")
    assert copied_url.path == "/new_book"
    assert copied_url.query == "query=value"

# --- Tests for URL Hashing ---
def test_url_account_id():
    """Test generating the Account ID hash from a URL."""
    url = URL.parse("acc://DefiDevs.acme/book")
    assert len(url.account_id()) == 32

def test_url_identity_id():
    """Test generating the Identity ID hash from a URL."""
    url = URL.parse("acc://DefiDevs.acme/book")
    assert len(url.identity_id()) == 32

def test_url_hash():
    """Test generating the full URL hash."""
    url = URL.parse("acc://DefiDevs.acme/book")
    assert len(url.hash()) == 32

# --- Updated Tests for Specific Scenarios ---
def test_lite_data_account():
    """Test parsing a lite data account URL."""
    url = URL.parse("acc://c26fd6ed6beafd197086c420bbc334f0cd4f05802b550e5d")
    assert url.authority == "acc://c26fd6ed6beafd197086c420bbc334f0cd4f05802b550e5d"
    assert url.path == ""
    assert str(url) == "acc://c26fd6ed6beafd197086c420bbc334f0cd4f05802b550e5d"

def test_accumulate_token_issuer():
    """Test parsing an Accumulate token issuer URL."""
    url = URL.parse("acc://DefiDevs.acme/token_name")
    assert url.authority == "acc://DefiDevs.acme"
    assert url.path == "/token_name"
    assert str(url) == "acc://DefiDevs.acme/token_name"

def test_url_parsing():
    url_str = "acc://DefiDevs.acme/data_account_name"
    print(f"TEST INPUT: {url_str}")
    try:
        url = URL.parse(url_str)
        print(f"PARSED URL: Scheme: acc, Authority: {url.authority}, Path: {url.path}")
    except ValueError as e:
        print(f"TEST FAILURE: {e}")

def test_url_marshal_unmarshal():
    url = URL.parse("acc://DefiDevs.acme/data_account_name")
    print(f"Original URL: Scheme: acc, Authority: {url.authority}, Path: {url.path}")
    
    marshaled = url.marshal()
    print(f"Serialized URL: {marshaled}")

    unmarshaled = URL.unmarshal(marshaled)
    print(f"Deserialized URL: Scheme: acc, Authority: {unmarshaled.authority}, Path: {unmarshaled.path}")

    assert url.authority == unmarshaled.authority
    assert url.path == unmarshaled.path

def test_missing_hash_error():
    """Test missing_hash function raises MissingHashError with the correct message."""
    url = "acc://example.com/tx"
    with pytest.raises(MissingHashError, match=f"{url} is not a transaction ID: Missing hash"):
        raise missing_hash(url)

def test_invalid_hash_error():
    """Test invalid_hash function raises InvalidHashError with the correct message."""
    url = "acc://example.com/tx"
    error_details = "Invalid checksum"
    with pytest.raises(InvalidHashError, match=f"{url} is not a transaction ID: Invalid hash. Details: {error_details}"):
        raise invalid_hash(url, error_details)

def test_wrong_scheme_error():
    """Test URL parsing raises WrongSchemeError when the scheme is incorrect."""
    invalid_url = "http://DefiDevs.acme"
    with pytest.raises(WrongSchemeError, match=f"Wrong scheme in URL: {invalid_url}. Expected 'acc://'."):
        URL.parse(invalid_url)

def test_empty_authority_error():
    """Test URL parsing raises ValueError when authority is empty."""
    invalid_url = "acc://"
    with pytest.raises(ValueError, match="Invalid URL: Authority cannot be empty"):
        URL.parse(invalid_url)

def test_is_key_page_url():
    """Test is_key_page_url method with valid and invalid key page URLs."""
    valid_url = URL(authority="acc://example.acme", path="/acc/accounts/123")
    assert valid_url.is_key_page_url() is True

    invalid_url_no_number = URL(authority="acc://example.acme", path="/acc/accounts/keypage")
    assert invalid_url_no_number.is_key_page_url() is False

    invalid_url_short_path = URL(authority="acc://example.acme", path="/acc/accounts")
    assert invalid_url_short_path.is_key_page_url() is False

def test_root_identity():
    """Test root_identity method returns a URL with only authority."""
    test_url = URL(authority="acc://DefiDevs.acme", path="/acc/accounts")
    root_url = test_url.root_identity()
    assert root_url.authority == "acc://DefiDevs.acme"
    assert root_url.path == ""

def test_identity():
    """Test identity method returns the correct ADI for Accumulate URLs."""
    adi = URL(authority="acc://DefiDevs.acme", path="")
    assert adi.identity().authority == "acc://DefiDevs.acme"
    assert adi.identity().path == ""

    key_book = URL(authority="acc://DefiDevs.acme", path="/book")
    assert key_book.identity().authority == "acc://DefiDevs.acme"
    assert key_book.identity().path == ""

    key_page = URL(authority="acc://DefiDevs.acme", path="/book/1")
    assert key_page.identity().authority == "acc://DefiDevs.acme"
    assert key_page.identity().path == ""

    account_url = URL(authority="acc://Example.acme", path="/accounts/user")
    assert account_url.identity().authority == "acc://Example.acme"
    assert account_url.identity().path == ""

def test_valid_utf8():
    """Test valid_utf8 method with valid and invalid UTF-8 components."""
    valid_url = URL(authority="acc://example.acme", path="/valid/path", query="param=1")
    assert valid_url.valid_utf8() is True

    invalid_url = URL(authority="acc://example.acme", path="/valid/path", query="\udc80")
    assert invalid_url.valid_utf8() is False
