# accumulate-python-client\tests\test_utils\test_formatting.py

import pytest
from decimal import Decimal
from accumulate.utils.formatting import (
    format_ac1, format_as1, format_ac2, format_as2, format_ac3, format_as3,
    format_fa, format_fs, format_btc, format_eth, format_mh, format_amount,
    format_big_amount, validate_precision, format_key_page_url,
    parse_key_page_url
)

# Test Address Formatting Functions
def test_format_ac1():
    hash_bytes = bytes.fromhex("abcdef" * 5)
    result = format_ac1(hash_bytes)
    assert result.startswith("AC1")
    assert len(result) > 3

def test_format_as1():
    seed = bytes.fromhex("abcdef" * 5)
    result = format_as1(seed)
    assert result.startswith("AS1")
    assert len(result) > 3

def test_format_ac2():
    hash_bytes = bytes.fromhex("abcdef" * 5)
    result = format_ac2(hash_bytes)
    assert result.startswith("AC2")
    assert len(result) > 3

def test_format_as2():
    seed = bytes.fromhex("abcdef" * 5)
    result = format_as2(seed)
    assert result.startswith("AS2")
    assert len(result) > 3

def test_format_ac3():
    hash_bytes = bytes.fromhex("abcdef" * 5)
    result = format_ac3(hash_bytes)
    assert result.startswith("AC3")
    assert len(result) > 3

def test_format_as3():
    seed = bytes.fromhex("abcdef" * 5)
    result = format_as3(seed)
    assert result.startswith("AS3")
    assert len(result) > 3

def test_format_fa():
    hash_bytes = bytes.fromhex("abcdef" * 5)
    result = format_fa(hash_bytes)
    assert len(result) > 0

def test_format_fs():
    seed = bytes.fromhex("abcdef" * 5)
    result = format_fs(seed)
    assert len(result) > 0

def test_format_btc():
    hash_bytes = bytes.fromhex("abcdef" * 5)
    result = format_btc(hash_bytes)
    assert result.startswith("BT")
    assert len(result) > 2

def test_format_eth():
    hash_bytes = bytes.fromhex("abcdef" * 5)  # Exactly 20 bytes
    result = format_eth(hash_bytes)
    assert result.startswith("0x")
    assert len(result) == 42  # '0x' + 40 hex characters

def test_format_eth_truncate():
    hash_bytes = bytes.fromhex("00" * 12 + "abcdef" * 2)  # More than 20 bytes
    result = format_eth(hash_bytes)
    assert result.startswith("0x")
    assert len(result) == 42  # Ensure consistent length
    assert result.endswith("abcdefabcdef")  # Last 20 bytes used

def test_format_eth_padding():
    hash_bytes = bytes.fromhex("abcdef")  # Less than 20 bytes
    result = format_eth(hash_bytes)
    assert result.startswith("0x")
    assert len(result) == 42  # Ensure consistent length
    assert result.endswith("abcdef".zfill(40))  # Padded with leading zeros

def test_format_mh():
    hash_bytes = bytes.fromhex("abcdef" * 5)
    result = format_mh(hash_bytes, "sha256")
    assert result.startswith("MH")
    assert len(result) > 2

def test_format_mh_invalid_algorithm():
    with pytest.raises(ValueError):
        format_mh(b"abcdef", "unsupported")

def test_format_mh_empty_hash_bytes():
    with pytest.raises(ValueError):
        format_mh(b"", "sha256")

# Test Amount Formatting Functions
def test_format_amount():
    result = format_amount(12345678, 4)
    assert result == "1234.5678"

def test_format_big_amount():
    result = format_big_amount(Decimal("987654321"), 5)
    assert result == "9876.54321"

def test_validate_precision():
    with pytest.raises(ValueError):
        validate_precision(1001)

# Test Key Page URL Functions
def test_format_key_page_url():
    result = format_key_page_url("http://example.com/keybook", 0)
    assert result == "http://example.com/keybook/1"

def test_parse_key_page_url():
    url = "http://example.com/keybook/2"
    result = parse_key_page_url(url)
    assert result == ("http://example.com/keybook", 1)

def test_parse_key_page_url_invalid():
    with pytest.raises(ValueError):
        parse_key_page_url("http://example.com/keybook")

# Edge Cases
def test_format_amount_zero_precision():
    result = format_amount(12345678, 0)
    assert result == "12345678"

def test_format_big_amount_zero_precision():
    result = format_big_amount(Decimal("12345678"), 0)
    assert result == "12345678"

def test_format_amount_invalid_precision():
    with pytest.raises(ValueError):
        format_amount(12345678, 1001)

def test_format_big_amount_invalid_precision():
    with pytest.raises(ValueError):
        format_big_amount(Decimal("12345678"), 1001)

def test_format_key_page_url_negative_index():
    with pytest.raises(ValueError):
        format_key_page_url("http://example.com/keybook", -1)
