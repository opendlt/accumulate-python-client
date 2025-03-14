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

# Helper functions to generate keys
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

@pytest.fixture
def signer():
    """Fixture to provide a fresh Signer instance for each test."""
    return Signer()

def test_set_public_key_ed25519(signer):
    private_key, _ = generate_ed25519_keys()
    signature = {"type": SignatureType.ED25519}
    signer.set_public_key(signature, private_key)
    # Expect the key to be stored under "publicKey"
    assert "publicKey" in signature

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

@pytest.mark.asyncio
async def test_sign_transaction_ed25519(signer):
    private_key, _ = generate_ed25519_keys()
    message = b"Test message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    # Set keys normally (ED25519)
    signer.set_keys(private_key)
    signature = await signer.sign_transaction(SignatureType.ED25519, message, txn_header)
    assert "signature" in signature

@pytest.mark.asyncio
async def test_sign_transaction_eth(signer):
    # For ETH, override get_private_key and get_public_key to bypass ed25519 conversion.
    private_key, public_key = generate_eth_keys()
    signer.get_private_key = lambda: private_key
    signer.get_public_key = lambda: public_key
    # Also, manually set the internal key state so that checks pass.
    signer._private_key = private_key  
    signer._public_key = public_key
    message = b"Test message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    signature = await signer.sign_transaction(SignatureType.ETH, message, txn_header)
    assert "signature" in signature
    # The returned dictionary should include common keys.
    assert "publicKey" in signature
    assert "signer" in signature

@pytest.mark.asyncio
async def test_sign_transaction_unsupported(signer):
    # Set dummy keys so that we pass the key-check.
    dummy_key, _ = generate_ed25519_keys()
    signer.set_keys(dummy_key)
    message = b"Test message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    with pytest.raises(ValueError, match="Unsupported signature type: SignatureType.UNKNOWN"):
        await signer.sign_transaction(SignatureType.UNKNOWN, message, txn_header)

def test_sign_rcd1(signer):
    private_key, _ = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature = signer.sign_rcd1(private_key, message)
    assert "signature" in signature

def test_verify_rcd1_valid(signer):
    private_key, public_key = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature_hex = signer.sign_rcd1(private_key, message)["signature"]
    signature_bytes = bytes.fromhex(signature_hex)
    assert signer.verify_rcd1(public_key, signature_bytes, message) is True

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
    metadata_hash = signer.calculate_metadata_hash(public_key, timestamp, signer_url, version, SignatureType.ED25519.value)
    assert isinstance(metadata_hash, bytes)

def test_calculate_signature_hash(signer):
    signature = Mock()
    signature.marshal_binary = Mock(return_value=b"Test signature data")
    result = signer.calculate_signature_hash(signature)
    assert isinstance(result, bytes)
    assert result == hashlib.sha256(b"Test signature data").digest()

def test_set_public_key_btclegacy():
    """Test setting public key for BTCLegacy signature type should raise an error."""
    signer_instance = Signer()
    signature = {"type": SignatureType.BTC_LEGACY}
    private_key = b"\x01" * 32
    with pytest.raises(ValueError, match="Cannot set the public key for SignatureType.BTC_LEGACY"):
        signer_instance.set_public_key(signature, private_key)

def test_set_public_key_rsa_sha256():
    """Test setting public key for RSA_SHA256 signature type."""
    signer_instance = Signer()
    signature = {"type": SignatureType.RSA_SHA256}
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signer_instance.set_public_key(signature, private_key)
    assert "publicKey" in signature
    assert isinstance(signature["publicKey"], str)
    pem_bytes = bytes.fromhex(signature["publicKey"])
    assert b"BEGIN PUBLIC KEY" in pem_bytes

def test_set_public_key_ecdsa_sha256():
    """Test setting public key for ECDSA_SHA256 signature type."""
    signer_instance = Signer()
    signature = {"type": SignatureType.ECDSA_SHA256}
    private_key = b"\x01" * 32  # Mock 256-bit private key
    signer_instance.set_public_key(signature, private_key)
    assert "publicKey" in signature
    assert isinstance(signature["publicKey"], str)
    pem_bytes = bytes.fromhex(signature["publicKey"])
    assert b"BEGIN PUBLIC KEY" in pem_bytes

@pytest.mark.asyncio
async def test_sign_transaction_btc():
    """Test signing a transaction with BTC signature type."""
    signer_instance = Signer()
    dummy_key = b"\x01" * 32
    # Set keys normally for BTC.
    signer_instance.set_keys(dummy_key)
    message = b"test_message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    result = await signer_instance.sign_transaction(SignatureType.BTC, dummy_key, txn_header)
    assert "signature" in result

@pytest.mark.asyncio
async def test_sign_transaction_rsa_sha256():
    """Test signing a transaction with RSA_SHA256 signature type."""
    signer_instance = Signer()
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Override get_private_key to return our RSA PEM.
    signer_instance.get_private_key = lambda: private_key
    # Manually set _private_key and _public_key using the RSA key.
    rsa_public = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer_instance._private_key = True  # Dummy truthy value to pass the check
    signer_instance._public_key = rsa_public
    message = b"test_message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    result = await signer_instance.sign_transaction(SignatureType.RSA_SHA256, message, txn_header)
    assert "signature" in result
    # Expect the RSA signature to be returned as a hex string.
    assert isinstance(result["signature"], str)

@pytest.mark.asyncio
async def test_sign_transaction_ecdsa_sha256():
    """Test signing a transaction with ECDSA_SHA256 signature type."""
    signer_instance = Signer()
    dummy_key = b"\x01" * 32
    signer_instance.set_keys(dummy_key)
    signer_instance.get_private_key = lambda: dummy_key
    message = b"test_message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    result = await signer_instance.sign_transaction(SignatureType.ECDSA_SHA256, dummy_key, txn_header)
    assert "signature" in result

def test_btc_address():
    """Test calculating a BTC address from the public key."""
    from accumulate.utils.hash_functions import btc_address
    public_key = b"\x02" * 33  # Mock compressed public key
    result = btc_address(public_key)
    assert isinstance(result, str)

def test_eth_address():
    """Test calculating an ETH address from the public key."""
    from accumulate.utils.hash_functions import eth_address
    public_key = b"\x04" * 65
    result = eth_address(public_key)
    assert isinstance(result, str)
