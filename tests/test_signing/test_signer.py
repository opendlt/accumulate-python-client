# accumulate-python-client\tests\test_signing\test_signer.py 

import pytest
import hashlib
from unittest.mock import Mock
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from eth_keys import keys as eth_keys
from eth_keys.exceptions import BadSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256K1
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

@pytest.fixture
def signer():
    """Fixture to provide a fresh Signer instance for each test."""
    return Signer()


def generate_ed25519_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def generate_eth_keys():
    private_key = eth_keys.PrivateKey(hashlib.sha256(b"test_key").digest())
    return private_key.to_bytes(), private_key.public_key.to_bytes()


def test_set_public_key_ed25519(signer):
    private_key, _ = generate_ed25519_keys()
    signature = {"type": SignatureType.ED25519}
    signer.set_public_key(signature, private_key)
    assert "public_key" in signature


def test_set_public_key_eth(signer):
    """Test setting public key for Ethereum."""
    private_key, _ = generate_eth_keys()
    signature = {"type": SignatureType.ETH}
    signer.set_public_key(signature, private_key)

    # Assert the ETH address is included
    assert "eth_address" in signature
    assert isinstance(signature["eth_address"], str)



def test_set_public_key_unsupported(signer):
    private_key = b"\x00" * 32
    signature = {"type": SignatureType.UNKNOWN}
    with pytest.raises(ValueError, match="Cannot set the public key for"):
        signer.set_public_key(signature, private_key)


def test_sign_transaction_ed25519(signer):
    private_key, _ = generate_ed25519_keys()
    message = b"Test message"
    signature = signer.sign_transaction(SignatureType.ED25519, private_key, message)
    assert "signature" in signature


def test_sign_transaction_eth(signer):
    private_key, _ = generate_eth_keys()
    message = b"Test message"
    signature = signer.sign_transaction(SignatureType.ETH, private_key, message)
    assert "signature" in signature
    assert "eth_address" in signature


def test_sign_transaction_unsupported(signer):
    private_key = b"\x00" * 32
    message = b"Test message"
    with pytest.raises(ValueError, match="Unsupported signature type"):
        signer.sign_transaction(SignatureType.UNKNOWN, private_key, message)


def test_sign_rcd1(signer):
    private_key, _ = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature = signer.sign_rcd1(private_key, message)
    assert "signature" in signature


def test_verify_rcd1_valid(signer):
    private_key, public_key = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature = signer.sign_rcd1(private_key, message)["signature"]
    assert signer.verify_rcd1(public_key, signature, message) is True


def test_verify_rcd1_invalid(signer):
    private_key, public_key = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature = b"\x00" * 64
    assert signer.verify_rcd1(public_key, signature, message) is False


def test_sha256_concat(signer):
    data1 = b"Test data 1"
    data2 = b"Test data 2"
    result = signer.sha256_concat(data1, data2)
    assert isinstance(result, bytes)
    assert result == hashlib.sha256(data1 + data2).digest()


def test_calculate_metadata_hash(signer):
    public_key = b"\x01" * 32
    timestamp = 1234567890
    signer_url = "acc://example.acme"
    version = 1
    metadata_hash = signer.calculate_metadata_hash(public_key, timestamp, signer_url, version)
    assert isinstance(metadata_hash, bytes)


def test_calculate_signature_hash(signer):
    signature = Mock()
    signature.marshal_binary = Mock(return_value=b"Test signature data")
    
    result = signer.calculate_signature_hash(signature)
    assert isinstance(result, bytes)
    assert result == hashlib.sha256(b"Test signature data").digest()


def test_set_public_key_btc():
    """Test setting public key for BTC and its address generation."""
    signer = Signer()
    signature = {"type": SignatureType.BTC}
    private_key = b"\x01" * 32

    signer.set_public_key(signature, private_key)

    assert "btc_address" in signature
    assert signature["btc_address"].startswith("1")



def test_set_public_key_btclegacy():
    """Test setting public key for BTCLegacy signature type."""
    signer = Signer()
    signature = {"type": SignatureType.BTCLegacy}
    private_key = b"\x01" * 32

    signer.set_public_key(signature, private_key)

    # Verify the public key is set
    assert "public_key" in signature
    assert isinstance(signature["public_key"], bytes)
    assert len(signature["public_key"]) == 65  # Uncompressed point format
    # Verify the BTC address is set
    assert "btc_address" in signature
    assert signature["btc_address"].startswith("1")





def test_set_public_key_rsa_sha256():
    """Test setting public key for RSA_SHA256 signature type."""
    signer = Signer()
    signature = {"type": SignatureType.RSA_SHA256}

    # Generate an RSA private key
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Call the set_public_key method
    signer.set_public_key(signature, private_key)

    # Validate the result
    assert "public_key" in signature
    assert isinstance(signature["public_key"], bytes)
    assert b"BEGIN PUBLIC KEY" in signature["public_key"]  # Verify PEM-encoded key



def test_set_public_key_ecdsa_sha256():
    """Test setting public key for ECDSA_SHA256 signature type."""
    signer = Signer()
    signature = {"type": SignatureType.ECDSA_SHA256}
    private_key = b"\x01" * 32  # Mock 256-bit private key

    signer.set_public_key(signature, private_key)

    # Verify the public key is set
    assert "public_key" in signature
    assert isinstance(signature["public_key"], bytes)
    assert b"BEGIN PUBLIC KEY" in signature["public_key"]  # Check for PEM-encoded key format


def test_sign_transaction_btc():
    """Test signing a transaction with BTC signature type."""
    signer = Signer()
    private_key = b"\x01" * 32  # Mock 256-bit private key
    message = b"test_message"

    result = signer.sign_transaction(SignatureType.BTC, private_key, message)
    assert "signature" in result


def test_sign_transaction_rsa_sha256():
    """Test signing a transaction with RSA_SHA256 signature type."""
    signer = Signer()

    # Generate an RSA private key
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    message = b"test_message"

    result = signer.sign_transaction(SignatureType.RSA_SHA256, private_key, message)
    assert "signature" in result
    assert isinstance(result["signature"], bytes)


def test_sign_transaction_ecdsa_sha256():
    """Test signing a transaction with ECDSA_SHA256 signature type."""
    signer = Signer()
    private_key = b"\x01" * 32  # Mock 256-bit private key
    message = b"test_message"

    result = signer.sign_transaction(SignatureType.ECDSA_SHA256, private_key, message)
    assert "signature" in result


def test_btc_address():
    """Test calculating a BTC address from the public key."""
    signer = Signer()
    public_key = b"\x02" * 33  # Mock compressed public key
    result = signer.btc_address(public_key)
    assert isinstance(result, str)


def test_eth_address():
    """Test calculating an ETH address from the public key."""
    signer = Signer()
    public_key = b"\x04" * 65
    result = signer.eth_address(public_key)
    assert isinstance(result, str)

