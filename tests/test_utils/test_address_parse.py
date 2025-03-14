# accumulate-python-client\tests\test_utils\test_address_parse.py

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
    parse_with_prefix,
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





# Mock function to simulate parse_wif behavior
def parse_wif_2(address: str):
    if address.startswith("5") or address.startswith("K") or address.startswith("L"):
        return {"type": "WIF", "address": address}
    raise ValidationError("Invalid WIF address format")

# Mock function to simulate parse_hex_or_base58 behavior
def parse_hex_or_base58_2(address: str):
    try:
        if all(c in "0123456789abcdefABCDEF" for c in address):  # Hexadecimal check
            return {"type": "Hex", "address": address}
        # Base58 decoding attempt
        base58.b58decode(address)
        return {"type": "Base58", "address": address}
    except Exception:
        raise ValidationError("Invalid Hex or Base58 format")

def test_parse_wif_valid_2():
    address = "5HueCGU8rMjxEXxiPuD5BDuKK8PJxhoHsPdXNPR7swpSmTnyc7Q"
    result = parse_wif(address).to_dict()
    assert result["type"] == "BTC"  # Assuming the type for WIF is "BTC"
    assert result["key"]  # Validate key presence


# Test parse_hex_or_base58 functionality
def test_parse_hex_or_base58_valid_hex_2():
    address = "abcdef1234567890"
    result = parse_hex_or_base58(address)
    assert result.get_type() == "RawHex"
    assert result.get_public_key_hash().hex() == address

def test_parse_hex_or_base58_valid_base58_2():
    address = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    result = parse_hex_or_base58(address)
    
    assert result.to_dict()["type"] == "Base58"
    
    # Re-encode the decoded hash to Base58 before comparison
    reencoded_address = base58.b58encode(result.hash).decode()
    
    assert reencoded_address == address



def test_parse_hex_or_base58_invalid_2():
    address = "Invalid$$Address"
    with pytest.raises(ValidationError, match="Invalid Hex or Base58 format") as exc_info:
        parse_hex_or_base58(address)
    print(f"DEBUG: Caught exception message: {str(exc_info.value)}")


def test_parse_fa_address_invalid_prefix_2():
    """Test ValidationError for an invalid FA address prefix."""
    address = "InvalidFAAddress"  # This address does not start with "FA"
    with pytest.raises(ValidationError, match="Invalid FA address prefix"):
        parse_fa_address(address)  # Directly test parse_fa_address


def test_parse_fa_address_invalid_prefix_in_parse():
    """Test ValidationError for invalid FA address prefix via parse."""
    address = "InvalidFAAddress"  # This address does not start with "FA"
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse(address)


# Test ValidationError for unknown address format
def test_parse_unknown_address_format_empty_2():
    address = ""
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse(address)

def test_parse_unknown_address_format_no_alnum_2():
    address = "!@#$%^&*()"
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse(address)

def test_parse_unknown_prefix_2():
    address = "XY1234567890abcdef"
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse(address)


def test_parse_wif4():
    """Test parsing a valid and invalid WIF (Wallet Import Format) address."""

    # Generate a valid WIF key
    valid_wif = encode_privkey(random_key(), 'wif')
    parsed = parse(valid_wif)

    assert isinstance(parsed, PrivateKey)
    assert parsed.type == "BTC"  
    assert parsed.key is not None

    # Invalid WIF (random string)
    invalid_wif = "5J1Fu8QmX8zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse(invalid_wif)



def test_parse_unknown_address_format2():
    """Test that an invalid address raises 'Unknown address format' error."""

    invalid_address = "xyz123"  # Clearly invalid format

    with pytest.raises(ValidationError, match="Unknown address format"):
        parse(invalid_address)

    # Edge case: Completely empty string
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse("")

# Test Invalid Fs Address Prefix
def test_parse_fs_address_invalid_prefix():
    """Test that an Fs address with an incorrect prefix raises a ValidationError."""
    invalid_fs_address = "FA1abcde..."  # Incorrect prefix
    with pytest.raises(ValidationError, match="Invalid Fs address prefix"):
        parse_fs_address(invalid_fs_address)

# Test Invalid Ethereum Address Format
def test_parse_eth_address_invalid_format():
    """Test that an incorrectly formatted Ethereum address raises a ValidationError."""
    invalid_eth_address = "xyz1234567890abcdefabcdefabcdefabcdefabcdef"  # Missing "0x"
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse_eth_address(invalid_eth_address)

# Test Ethereum Address Incorrect Length
def test_parse_eth_address_invalid_length():
    """Test that an Ethereum address with an incorrect byte length raises a ValidationError."""
    invalid_eth_address = "0xabcdef"  # Too short
    with pytest.raises(ValidationError, match="Unknown address format"):
        parse_eth_address(invalid_eth_address)

# Test Invalid MH Address Decoding Failure
def test_parse_mh_address_invalid_decoding():
    """Test that an MH address with invalid Base58 decoding raises a ValidationError."""
    invalid_mh_address = "MH$$$%%%^^^"  # Invalid Base58 characters
    with pytest.raises(ValidationError, match="Invalid MH address: decoding failed"):
        parse_mh_address(invalid_mh_address)



# Test Invalid Prefix in `parse_with_prefix`
def test_parse_with_prefix_invalid_prefix():
    """Test that `parse_with_prefix` raises ValidationError for an incorrect prefix."""
    invalid_address = "XX12345"  # Should start with a specific prefix but doesn't
    with pytest.raises(ValidationError, match="Invalid prefix for FA"):
        parse_with_prefix(invalid_address, length=32, prefix="FA")  # Expect FA prefix but got XX


# Test Invalid Length in `parse_with_prefix`
def test_parse_with_prefix_invalid_length():
    """Test that `parse_with_prefix` raises ValidationError for an incorrect length."""
    prefix = "FA"
    valid_payload = base58.b58encode(b"\x00" * 30).decode()  # Should be 32 bytes but is only 30
    invalid_address = prefix + valid_payload

    with pytest.raises(ValidationError, match="Invalid length for FA address"):
        parse_with_prefix(invalid_address, length=32, prefix=prefix)


# Test Invalid WIF Length in `parse_wif`
def test_parse_wif_invalid_length():
    """Test that `parse_wif` raises ValidationError for an incorrect WIF key length."""
    invalid_wif = base58.b58encode(b"\x80" + b"\x00" * 30).decode()  # Too short (must be 32 bytes + metadata)
    with pytest.raises(ValidationError, match="Invalid WIF length"):
        parse_wif(invalid_wif)

# Test `is_wif_key` Returning False for Incorrect Prefix
def test_is_wif_key_invalid_prefix():
    """Test that `is_wif_key` returns False for incorrect WIF prefixes."""
    invalid_wif = "X" * 52  # Should start with "5", "K", or "L"
    assert is_wif_key(invalid_wif) is False

# Test `is_wif_key` Returning False for Incorrect Length
def test_is_wif_key_invalid_length():
    """Test that `is_wif_key` returns False for incorrect WIF key length."""
    invalid_wif = "5" * 49  # Should be 51 or 52 characters long
    assert is_wif_key(invalid_wif) is False

# Test `is_wif_key` Returning False on Exception Handling
def test_is_wif_key_exception_handling():
    """Test that `is_wif_key` returns False when decoding fails."""
    invalid_wif = "5J1Fu8QmX8$$$$$$$$$$$"  # Invalid Base58 characters
    assert is_wif_key(invalid_wif) is False
