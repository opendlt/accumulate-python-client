# C:\Accumulate_Stuff\accumulate-python-client\tests\test_utils\test_address_parse.py

import pytest
import base58
from bitcoin import encode_privkey, random_key
import hashlib
from accumulate.utils.address_parse import (
    parse,
    parse_ac_address,
    parse_as_address,
    parse_fa_address,
    parse_fs_address,
    parse_btc_address,
    parse_eth_address,
    parse_mh_address,
    parse_hex_or_base58,
    parse_wif,
    parse_lite,
    verify_checksum,
    is_wif_key,
    ValidationError,
)
from accumulate.models.signatures import PublicKeyHash, PrivateKey, Lite

# --- Helper Functions ---
def create_valid_address(prefix: str, data: bytes, checksum_length: int = 4, binary_prefix: bytes = b"") -> str:
    """
    Create a valid address by combining the prefix with Base58-encoded payload and checksum.

    :param prefix: The string prefix for the address (e.g., "FA").
    :param data: The binary data for the address.
    :param checksum_length: The length of the checksum in bytes.
    :param binary_prefix: The binary prefix for certain address types (e.g., Factom keys).
    :return: The complete address as a string.
    """
    # Combine the binary prefix with the data
    payload = binary_prefix + data
    # Calculate checksum
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:checksum_length]
    # Base58 encode the payload and checksum
    encoded_data = base58.b58encode(payload + checksum).decode()
    
    # Return the full address, including the readable prefix
    return prefix + encoded_data




# --- Tests ---
def test_parse_ac_address():
    data = b"a" * 32
    valid_address = create_valid_address("AC1", data)
    parsed = parse_ac_address(valid_address)
    assert isinstance(parsed, PublicKeyHash)
    assert parsed.type == "ED25519"
    assert parsed.hash == data

    invalid_address = create_valid_address("AC4", data)  # Invalid prefix
    with pytest.raises(ValidationError):
        parse_ac_address(invalid_address)

    # Generate a corrupted address by altering the checksum
    corrupted_address = valid_address[:-1] + ("X" if valid_address[-1] != "X" else "Y")
    with pytest.raises(ValidationError):
        parse_ac_address(corrupted_address)

def test_parse_as_address():
    data = b"b" * 32
    valid_address = create_valid_address("AS1", data)
    parsed = parse_as_address(valid_address)
    assert isinstance(parsed, PrivateKey)
    assert parsed.type == "ED25519"
    assert parsed.key == data

    # Test invalid prefix
    invalid_address = create_valid_address("AS4", data)  # Invalid prefix
    with pytest.raises(ValidationError):
        parse_as_address(invalid_address)

    # Corrupt the checksum of the valid address
    corrupted_address = valid_address[:-1] + ("X" if valid_address[-1] != "X" else "Y")
    with pytest.raises(ValidationError):
        parse_as_address(corrupted_address)


def test_parse_fa_address():
    data = b"c" * 32
    # Generate a valid FA address
    valid_address = create_valid_address("FA", data, binary_prefix=b"\x5f\xb1")  # Include binary prefix
    parsed = parse_fa_address(valid_address)
    assert isinstance(parsed, PublicKeyHash)
    assert parsed.type == "RCD1"
    assert parsed.hash == data

    # Generate an invalid FA address with an incorrect binary prefix
    invalid_address = create_valid_address("FA", data, binary_prefix=b"\x5f\xb2")  # Invalid binary prefix
    with pytest.raises(ValidationError):
        parse_fa_address(invalid_address)

def test_parse_fs_address():
    data = b"d" * 32
    # Generate a valid Fs address
    valid_address = create_valid_address("Fs", data, binary_prefix=b"\x64\x78")  # Include binary prefix
    parsed = parse_fs_address(valid_address)
    assert isinstance(parsed, PrivateKey)
    assert parsed.type == "RCD1"
    assert parsed.key == data

    # Generate an invalid Fs address with an incorrect binary prefix
    invalid_address = create_valid_address("Fs", data, binary_prefix=b"\x64\x79")  # Invalid binary prefix
    with pytest.raises(ValidationError):
        parse_fs_address(invalid_address)



def test_parse_btc_address():
    data = b"e" * 20
    valid_address = create_valid_address("BT", data, binary_prefix=b"\x00")
    parsed = parse_btc_address(valid_address)
    assert isinstance(parsed, PublicKeyHash)
    assert parsed.type == "BTC"
    assert parsed.hash == data

    # Generate an invalid Base58-encoded address
    invalid_base58_data = base58.b58encode(b"invalid_data").decode()  # Base58-compatible, semantically invalid
    invalid_address = "BT" + invalid_base58_data
    with pytest.raises(ValidationError):
        parse_btc_address(invalid_address)



def test_parse_eth_address():
    valid_address = "0x" + "f" * 40
    parsed = parse_eth_address(valid_address)
    assert isinstance(parsed, PublicKeyHash)
    assert parsed.type == "ETH"
    assert parsed.hash == bytes.fromhex("f" * 40)

    with pytest.raises(ValidationError):
        parse_eth_address("0xshort")  # Invalid ETH length

    with pytest.raises(ValidationError):
        parse_eth_address("invalid")  # Missing prefix

def test_parse_mh_address():
    data = b"g" * 32
    valid_address = "MH" + base58.b58encode(data).decode()
    parsed = parse_mh_address(valid_address)
    assert isinstance(parsed, PublicKeyHash)
    assert parsed.type == "Multihash"
    assert parsed.hash == data

    with pytest.raises(ValidationError):
        parse_mh_address("invalid")  # Invalid prefix

def test_parse_hex_or_base58():
    hex_data = "f" * 64
    parsed_hex = parse_hex_or_base58(hex_data)
    assert isinstance(parsed_hex, PublicKeyHash)
    assert parsed_hex.type == "RawHex"
    assert parsed_hex.hash == bytes.fromhex(hex_data)

    base58_data = base58.b58encode(b"h" * 32).decode()
    parsed_base58 = parse_hex_or_base58(base58_data)
    assert isinstance(parsed_base58, PublicKeyHash)
    assert parsed_base58.type == "Base58"
    assert parsed_base58.hash == base58.b58decode(base58_data)

    with pytest.raises(ValidationError):
        parse_hex_or_base58("invalid")

def test_parse_wif():
    valid_wif = base58.b58encode(b"5" + b"i" * 36).decode()
    parsed = parse_wif(valid_wif)
    assert isinstance(parsed, PrivateKey)
    assert parsed.type == "BTC"

    with pytest.raises(ValidationError):
        parse_wif("invalid")

def test_verify_checksum():
    data = b"j" * 32
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    verify_checksum(data, checksum)  # Should not raise

    with pytest.raises(ValidationError):
        verify_checksum(data, b"wrong")  # Invalid checksum

def test_is_wif_key():

    # Generate a valid WIF key dynamically
    private_key = random_key()
    VALID_WIF = encode_privkey(private_key, 'wif')
    INVALID_WIF = "invalid"

    assert is_wif_key(VALID_WIF) is True
    assert is_wif_key(INVALID_WIF) is False



def test_parse_lite():
    lite_address = "acc://example.lite"
    parsed = parse_lite(lite_address)
    assert isinstance(parsed, Lite)
    assert parsed.url == lite_address


def test_parse_invalid_inputs():
    invalid_inputs = [
        "acc://",  # Incomplete Lite address
        "   ",     # Only whitespace
        "++++",    # Symbols only
        "!@#$%",   # Special characters
        "0x123",   # Invalid ETH address (too short)
        "MH!",     # Invalid MH address with symbols
        "fakeAddress123",  # Invalid alphanumeric
    ]
    for address in invalid_inputs:
        with pytest.raises(ValidationError, match="Unknown address format"):
            parse(address)




def test_parse():
    # Short address
    with pytest.raises(ValidationError, match="Unknown address format"):  # Updated to match standardized message
        parse("sho")  # Too short for any valid prefix

    # Valid cases
    data = b"a" * 32
    valid_ac1_address = create_valid_address("AC1", data)
    assert isinstance(parse("acc://example.lite"), Lite)
    assert isinstance(parse(valid_ac1_address), PublicKeyHash)

    valid_as1_address = create_valid_address("AS1", b"b" * 32)
    assert isinstance(parse(valid_as1_address), PrivateKey)

    valid_fa_address = create_valid_address("FA", b"c" * 32, binary_prefix=b"\x5f\xb1")
    assert isinstance(parse(valid_fa_address), PublicKeyHash)

    valid_fs_address = create_valid_address("Fs", b"d" * 32, binary_prefix=b"\x64\x78")
    assert isinstance(parse(valid_fs_address), PrivateKey)

    valid_bt_address = create_valid_address("BT", b"e" * 20, binary_prefix=b"\x00")
    assert isinstance(parse(valid_bt_address), PublicKeyHash)

    valid_eth_address = "0x" + "f" * 40
    assert isinstance(parse(valid_eth_address), PublicKeyHash)

    valid_mh_address = "MH" + base58.b58encode(b"g" * 32).decode()
    assert isinstance(parse(valid_mh_address), PublicKeyHash)

    # Invalid formats
    invalid_addresses = [
        "unknown",  # Generic invalid
        "!@#$%",    # Special characters
        "short",    # Too short but alphanumeric
        " " * 10,   # Whitespace
        "++++",     # Symbols only
        "acc://",   # Incomplete Lite address
        "0x123",    # Invalid ETH address (too short)
        "MH!",      # Invalid MH address with symbols
        "fakeAddress123",  # Invalid alphanumeric
    ]
    for address in invalid_addresses:
        with pytest.raises(ValidationError, match="Unknown address format"):
            parse(address)
