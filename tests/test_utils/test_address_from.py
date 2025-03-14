# accumulate-python-client\tests\test_utils\test_address_from.py

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from eth_keys import keys as eth_keys
from accumulate.utils.address_from import (
    from_ed25519_public_key,
    from_ed25519_private_key,
    from_rsa_public_key,
    from_rsa_private_key,
    from_ecdsa_public_key,
    from_ecdsa_private_key,
    from_eth_private_key,
    from_private_key_bytes,
)
from accumulate.models.signatures import PublicKey, PrivateKey
from accumulate.models.signature_types import SignatureType
import base64

# Constants
VALID_ED25519_PUBLIC_KEY = b"\x01" * 32
VALID_ED25519_PRIVATE_KEY = b"\x01" * 64
INVALID_PUBLIC_KEY = b"\x01" * 16
INVALID_PRIVATE_KEY = b"\x01" * 16

# Fixtures
@pytest.fixture
def rsa_private_key():
    """Fixture to generate an RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def ecdsa_private_key():
    """Fixture to generate an ECDSA private key."""
    return ec.generate_private_key(ec.SECP256R1())


# --- Tests for Ed25519 Key Conversion ---
def test_from_ed25519_public_key_valid():
    result = from_ed25519_public_key(VALID_ED25519_PUBLIC_KEY)
    assert isinstance(result, PublicKey)
    assert result.type == SignatureType.ED25519
    assert result.key == VALID_ED25519_PUBLIC_KEY


def test_from_ed25519_public_key_invalid_length():
    with pytest.raises(ValueError, match="Invalid Ed25519 public key length."):
        from_ed25519_public_key(INVALID_PUBLIC_KEY)


def test_from_ed25519_private_key_valid():
    result = from_ed25519_private_key(VALID_ED25519_PRIVATE_KEY)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.ED25519
    assert result.key == VALID_ED25519_PRIVATE_KEY[:32]


    # Dynamically compute the expected public key
    private_key = Ed25519PrivateKey.from_private_bytes(VALID_ED25519_PRIVATE_KEY[:32])
    expected_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    print("Expected:", VALID_ED25519_PRIVATE_KEY)
    print("Actual:", result.key)
    assert result.public_key.key == expected_public_key


def test_from_ed25519_private_key_invalid_length():
    with pytest.raises(ValueError, match="Invalid Ed25519 private key length."):
        from_ed25519_private_key(INVALID_PRIVATE_KEY)


# --- Tests for RSA Key Conversion ---
def test_from_rsa_public_key(rsa_private_key):
    public_key = rsa_private_key.public_key()
    result = from_rsa_public_key(public_key)
    assert isinstance(result, PublicKey)
    assert result.type == SignatureType.RSA_SHA256
    assert b"-----BEGIN PUBLIC KEY-----" in result.key


def test_from_rsa_private_key(rsa_private_key):
    result = from_rsa_private_key(rsa_private_key)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.RSA_SHA256
    assert b"-----BEGIN PUBLIC KEY-----" in result.public_key.key
    assert b"-----BEGIN PRIVATE KEY-----" in result.key


# --- Tests for ECDSA Key Conversion ---
def test_from_ecdsa_public_key(ecdsa_private_key):
    public_key = ecdsa_private_key.public_key()
    result = from_ecdsa_public_key(public_key)
    assert isinstance(result, PublicKey)
    assert result.type == SignatureType.ECDSA_SHA256
    assert b"-----BEGIN PUBLIC KEY-----" in result.key


def test_from_ecdsa_private_key(ecdsa_private_key):
    result = from_ecdsa_private_key(ecdsa_private_key)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.ECDSA_SHA256
    assert b"-----BEGIN PUBLIC KEY-----" in result.public_key.key
    assert b"-----BEGIN PRIVATE KEY-----" in result.key


# --- Tests for Ethereum Key Conversion ---
def test_from_eth_private_key():
    eth_private_key_bytes = b"\x01" * 32
    result = from_eth_private_key(eth_private_key_bytes)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.ECDSA_SHA256
    eth_key = eth_keys.PrivateKey(eth_private_key_bytes)
    assert result.public_key.key == eth_key.public_key.to_bytes()


# --- Tests for Generic Key Conversion ---
def test_from_private_key_bytes_ed25519():
    result = from_private_key_bytes(VALID_ED25519_PRIVATE_KEY, SignatureType.ED25519)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.ED25519


def test_from_private_key_bytes_rsa(rsa_private_key):
    private_key_bytes = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    result = from_private_key_bytes(private_key_bytes, SignatureType.RSA_SHA256)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.RSA_SHA256


def test_from_private_key_bytes_invalid_type():
    with pytest.raises(ValueError, match="Unsupported signature type: INVALID_TYPE"):
        from_private_key_bytes(b"\x01" * 32, "INVALID_TYPE")





def test_from_ed25519_private_key_valid_32_bytes():
    """Test Ed25519 private key conversion with 32-byte key."""
    valid_32_byte_key = b"\x01" * 32  # A valid 32-byte private key
    result = from_ed25519_private_key(valid_32_byte_key)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.ED25519
    assert result.key == valid_32_byte_key

    # Check the derived public key
    private_key = Ed25519PrivateKey.from_private_bytes(valid_32_byte_key)
    expected_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    assert result.public_key.key == expected_public_key


def test_from_private_key_bytes_invalid_rsa_key():
    """Test RSA private key validation raises an error for invalid key."""
    invalid_key = b"invalid_rsa_key"
    with pytest.raises(ValueError, match="Could not deserialize key data."):
        from_private_key_bytes(invalid_key, SignatureType.RSA_SHA256)


def test_from_private_key_bytes_invalid_ecdsa_key():
    """Test ECDSA private key validation raises an error for invalid key."""
    invalid_key = b"invalid_ecdsa_key"
    with pytest.raises(ValueError, match="Could not deserialize key data."):
        from_private_key_bytes(invalid_key, SignatureType.ECDSA_SHA256)

def test_from_private_key_bytes_valid_ecdsa_key(ecdsa_private_key):
    """Test valid ECDSA private key conversion."""
    private_key_bytes = ecdsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    result = from_private_key_bytes(private_key_bytes, SignatureType.ECDSA_SHA256)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.ECDSA_SHA256
    assert b"-----BEGIN PRIVATE KEY-----" in result.key
    assert b"-----BEGIN PUBLIC KEY-----" in result.public_key.key


def test_from_private_key_bytes_eth_key():
    """Test Ethereum private key conversion."""
    eth_private_key_bytes = b"\x01" * 32
    result = from_private_key_bytes(eth_private_key_bytes, SignatureType.ETH)
    assert isinstance(result, PrivateKey)
    assert result.type == SignatureType.ECDSA_SHA256
    eth_key = eth_keys.PrivateKey(eth_private_key_bytes)
    assert result.public_key.key == eth_key.public_key.to_bytes()
