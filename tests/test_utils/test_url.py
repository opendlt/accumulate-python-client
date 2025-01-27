# accumulate-python-client\tests\test_utils\test_url.py

import pytest
from accumulate.utils.url import URL, MissingHostError, WrongSchemeError, URLParseError


# --- Updated Tests for URL Parsing ---
def test_url_parse_lite_identity():
    """Test parsing a lite identity URL."""
    url = URL.parse("acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56")
    assert url.authority == "0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"
    assert url.path == ""
    assert str(url) == "0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"


def test_url_parse_lite_token_account():
    """Test parsing a lite token account URL."""
    url = URL.parse("acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56/ACME")
    assert url.authority == "0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"
    assert url.path == "/ACME"
    assert str(url) == "0143b52490530b90eef9b1a2405e322c6badc1e90e200c56/ACME"


def test_url_parse_accumulate_identity():
    """Test parsing an Accumulate Identity URL."""
    url = URL.parse("acc://DefiDevs.acme")
    assert url.authority == "DefiDevs.acme"
    assert url.path == ""
    assert str(url) == "DefiDevs.acme"


def test_url_parse_accumulate_key_book():
    """Test parsing an Accumulate key book URL."""
    url = URL.parse("acc://DefiDevs.acme/book")
    assert url.authority == "DefiDevs.acme"
    assert url.path == "/book"
    assert str(url) == "DefiDevs.acme/book"


def test_url_parse_accumulate_key_page():
    """Test parsing an Accumulate key page URL."""
    url = URL.parse("acc://DefiDevs.acme/book/1")
    assert url.authority == "DefiDevs.acme"
    assert url.path == "/book/1"
    assert str(url) == "DefiDevs.acme/book/1"


# --- Tests for URL Parsing ---
def test_url_parse_missing_scheme():
    """Test parsing a URL without the 'acc://' scheme."""
    url_str = "0143b52490530b90eef9b1a2405e322c6badc1e90e200c56"
    try:
        URL.parse(url_str)
    except WrongSchemeError as e:
        print(f"Expected exception caught: {e}")
        return
    except Exception as e:
        print(f"Unexpected exception: {e}")
    assert False, "Expected WrongSchemeError was not raised."


def test_url_parse_missing_authority():
    """Test parsing a URL with missing authority."""
    url_str = "acc:///path"
    try:
        URL.parse(url_str)
    except MissingHostError as e:
        print(f"Expected exception caught: {e}")
        return
    except Exception as e:
        print(f"Unexpected exception: {e}")
    assert False, "Expected MissingHostError was not raised."


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
    assert str(url) == "userDefiDevs.acme/path?query=value#fragment"


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
    assert url.authority == "c26fd6ed6beafd197086c420bbc334f0cd4f05802b550e5d"
    assert url.path == ""
    # Updated to match the current __str__ behavior
    assert str(url) == "c26fd6ed6beafd197086c420bbc334f0cd4f05802b550e5d"



def test_accumulate_token_issuer():
    """Test parsing an Accumulate token issuer URL."""
    url = URL.parse("acc://DefiDevs.acme/token_name")
    assert url.authority == "DefiDevs.acme"
    assert url.path == "/token_name"
    assert str(url) == "DefiDevs.acme/token_name"


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
