# accumulate-python-client\tests\test_models\test_signature_types.py

import pytest
from accumulate.models.signature_types import SignatureType


def test_signature_type_enum_values():
    """Test SignatureType enum values."""
    assert SignatureType.UNKNOWN.value == 0
    assert SignatureType.ED25519.value == 1
    assert SignatureType.LEGACY_ED25519.value == 2
    assert SignatureType.ECDSA_SHA256.value == 3
    assert SignatureType.RSA_SHA256.value == 4
    assert SignatureType.RCD1.value == 5
    assert SignatureType.BTC.value == 6
    assert SignatureType.BTCLegacy.value == 7
    assert SignatureType.ETH.value == 8
    assert SignatureType.RECEIPT.value == 9
    assert SignatureType.PARTITION.value == 10
    assert SignatureType.REMOTE.value == 11
    assert SignatureType.DELEGATED.value == 12
    assert SignatureType.AUTHORITY.value == 13
    assert SignatureType.TYPED_DATA.value == 14


def test_signature_type_enum_names():
    """Test SignatureType enum names."""
    assert SignatureType(0) == SignatureType.UNKNOWN
    assert SignatureType(1) == SignatureType.ED25519
    assert SignatureType(2) == SignatureType.LEGACY_ED25519
    assert SignatureType(3) == SignatureType.ECDSA_SHA256
    assert SignatureType(4) == SignatureType.RSA_SHA256
    assert SignatureType(5) == SignatureType.RCD1
    assert SignatureType(6) == SignatureType.BTC
    assert SignatureType(7) == SignatureType.BTCLegacy
    assert SignatureType(8) == SignatureType.ETH
    assert SignatureType(9) == SignatureType.RECEIPT
    assert SignatureType(10) == SignatureType.PARTITION
    assert SignatureType(11) == SignatureType.REMOTE
    assert SignatureType(12) == SignatureType.DELEGATED
    assert SignatureType(13) == SignatureType.AUTHORITY
    assert SignatureType(14) == SignatureType.TYPED_DATA


def test_signature_type_enum_invalid():
    """Test SignatureType enum invalid values."""
    with pytest.raises(ValueError):
        SignatureType(99)


def test_signature_type_enum_str():
    """Test SignatureType enum string representation."""
    assert str(SignatureType.UNKNOWN) == "SignatureType.UNKNOWN"
    assert str(SignatureType.ED25519) == "SignatureType.ED25519"
    assert str(SignatureType.ECDSA_SHA256) == "SignatureType.ECDSA_SHA256"
    assert str(SignatureType.RSA_SHA256) == "SignatureType.RSA_SHA256"
    assert str(SignatureType.AUTHORITY) == "SignatureType.AUTHORITY"
    assert str(SignatureType.TYPED_DATA) == "SignatureType.TYPED_DATA"


def test_signature_type_enum_iterable():
    """Test iterating over all SignatureType enum values."""
    signature_types = list(SignatureType)
    assert len(signature_types) == 15
    assert SignatureType.UNKNOWN in signature_types
    assert SignatureType.ED25519 in signature_types
    assert SignatureType.TYPED_DATA in signature_types


@pytest.mark.parametrize(
    "signature_type, expected_value",
    [
        (SignatureType.UNKNOWN, 0),
        (SignatureType.ED25519, 1),
        (SignatureType.ECDSA_SHA256, 3),
        (SignatureType.RSA_SHA256, 4),
        (SignatureType.AUTHORITY, 13),
    ]
)
def test_signature_type_enum_parametrized(signature_type, expected_value):
    """Test SignatureType enum values using parameterized tests."""
    assert signature_type.value == expected_value
