# accumulate-python-client\tests\test_models\test_txid.py

import re
import pytest
from accumulate.models.txid import TxID
from accumulate.utils.url import URL, MissingHashError, InvalidHashError


def test_txid_initialization():
    """Test the initialization of a TxID instance with a valid URL and hash."""
    url = URL.parse("acc://staking.acme/path")
    tx_hash = bytes.fromhex("00" * 32)  # 32-byte zero hash
    txid = TxID(url, tx_hash)

    assert txid.url == url
    assert txid.tx_hash == tx_hash


def test_txid_initialization_invalid_url():
    """Test the initialization of a TxID instance with an invalid URL."""
    with pytest.raises(ValueError, match="TxID must be initialized with a URL instance."):
        TxID("not-a-url", bytes.fromhex("00" * 32))


def test_txid_initialization_invalid_hash():
    """Test the initialization of a TxID instance with an invalid hash."""
    url = URL.parse("acc://staking.acme/path")
    with pytest.raises(ValueError, match="Transaction hash must be a 32-byte value."):
        TxID(url, b"short-hash")


def test_txid_parse_valid():
    """Test parsing a valid TxID."""
    txid_str = "acc://509e263b5b7c17a1f8b8a8a02a3e925b3abc448f3a5be6d5c3a1de3c64bb1aec@staking.acme/tokens"
    txid = TxID.parse(txid_str)

    # Note: The new URL parsing retains the scheme in authority.
    assert txid.url.authority == "acc://staking.acme"
    assert txid.url.user_info == ""  # user_info should be removed in the clean URL
    assert txid.tx_hash == bytes.fromhex("509e263b5b7c17a1f8b8a8a02a3e925b3abc448f3a5be6d5c3a1de3c64bb1aec")
    assert txid.url.path == "/tokens"


def test_txid_parse_missing_hash():
    """Test TxID missing the TxHash."""
    txid_str = "acc://@staking.acme/tokens"
    try:
        TxID.parse(txid_str)
        pytest.fail("Expected an exception for missing hash but none was raised.")
    except (MissingHashError, ValueError) as e:
        assert any(
            pattern in str(e)
            for pattern in [
                "TxID missing hash",  # For MissingHashError
                "Invalid URL: '@' must separate valid user info and authority.",  # For ValueError
            ]
        )


def test_txid_parse_invalid_hash():
    """Test parsing a TxID string with an invalid hash."""
    txid_str = "acc://invalidhash@staking.acme/tokens"
    try:
        TxID.parse(txid_str)
    except (InvalidHashError, ValueError) as e:
        assert re.match(r"Invalid transaction hash format.*", str(e))
    else:
        pytest.fail("Expected InvalidHashError or ValueError but no exception was raised.")


def test_txid_parse_missing_at():
    """Test TxID missing the '@' separator."""
    txid_str = "acc://staking.acme/tokens"
    with pytest.raises(ValueError, match=r"Invalid TxID structure: .*"):
        TxID.parse(txid_str)


def test_txid_parse_invalid_url_ending_with_at():
    """Test parsing a URL that ends with '@'."""
    txid_str = "acc://staking.acme@"
    with pytest.raises(MissingHashError, match=r"TxID missing hash: acc://staking.acme@"):
        TxID.parse(txid_str)


def test_txid_parse_invalid_domain():
    """Test TxID with an invalid domain ending with .com."""
    txid_str = "acc://509e263b5b7c17a1f8b8a8a02a3e925b3abc448f3a5be6d5c3a1de3c64bb1aec@invalid.com/tokens"
    with pytest.raises(ValueError, match=r"Invalid authority domain: .*invalid\.com.*Domains ending with '\.com' are not allowed\."):
        TxID.parse(txid_str)


def test_txid_parse_invalid_hash_in_path():
    """Test parsing a TxID with an invalid '@' in the path."""
    txid_str = "acc://staking.acme/tokens@extra"
    with pytest.raises(
        MissingHashError,
        match=r"TxID missing hash: acc://staking.acme/tokens@extra"
    ):
        TxID.parse(txid_str)


def test_txid_as_url():
    """Test constructing a URL representation of the TxID."""
    url = URL.parse("acc://staking.acme/path")
    tx_hash = bytes.fromhex("00" * 32)
    txid = TxID(url, tx_hash)

    expected_url = url.with_user_info(tx_hash.hex())
    assert txid.as_url() == expected_url


def test_txid_account():
    """Test retrieving the account URL from a TxID."""
    url = URL.parse("acc://staking.acme/path")
    tx_hash = bytes.fromhex("00" * 32)
    txid = TxID(url, tx_hash)

    assert txid.account() == url


def test_txid_compare():
    """Test lexicographical comparison of two TxIDs."""
    url = URL.parse("acc://staking.acme/path")
    txid1 = TxID(url, bytes.fromhex("00" * 32))
    txid2 = TxID(url, bytes.fromhex("ff" * 32))

    assert txid1.compare(txid2) == -1
    assert txid2.compare(txid1) == 1
    assert txid1.compare(txid1) == 0


def test_txid_compare_invalid():
    """Test comparison with an invalid object."""
    url = URL.parse("acc://staking.acme/path")
    txid = TxID(url, bytes.fromhex("00" * 32))

    with pytest.raises(ValueError, match="Comparison must be between two TxIDs"):
        txid.compare("not-a-txid")


def test_txid_equality():
    """Test equality of TxID instances."""
    url = URL.parse("acc://staking.acme/path")
    txid1 = TxID(url, bytes.fromhex("00" * 32))
    txid2 = TxID(url, bytes.fromhex("00" * 32))
    txid3 = TxID(url, bytes.fromhex("ff" * 32))

    assert txid1 == txid2
    assert txid1 != txid3


def test_txid_hash():
    """Test hashing of TxID instances."""
    url = URL.parse("acc://staking.acme/path")
    txid = TxID(url, bytes.fromhex("00" * 32))

    expected_hash = hash((str(url), bytes.fromhex("00" * 32)))
    assert hash(txid) == expected_hash


def test_txid_str():
    """Test string representation of TxID."""
    url = URL.parse("acc://staking.acme/path")
    tx_hash = bytes.fromhex("00" * 32)
    txid = TxID(url, tx_hash)

    expected_str = f"{str(url)}@{tx_hash.hex()}"
    # This now expects the full URL with scheme in the authority.
    assert str(txid) == expected_str


def test_txid_json():
    """Test JSON serialization of TxID."""
    url = URL.parse("acc://staking.acme/path")
    tx_hash = bytes.fromhex("00" * 32)
    txid = TxID(url, tx_hash)

    json_str = txid.json()
    expected_json = '{"url": "acc://staking.acme/path", "hash": "0000000000000000000000000000000000000000000000000000000000000000"}'
    assert json_str == expected_json


def test_txid_from_json():
    """Test deserialization of TxID from JSON."""
    json_str = '{"url": "acc://staking.acme/path", "hash": "0000000000000000000000000000000000000000000000000000000000000000"}'
    txid = TxID.from_json(json_str)

    assert txid.url == URL.parse("acc://staking.acme/path")
    assert txid.tx_hash == bytes.fromhex("00" * 32)

