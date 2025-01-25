# C:\Accumulate_Stuff\accumulate-python-client\tests\test_signing\test_signer.py 

import pytest
import hashlib
from unittest.mock import Mock
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256K1
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from accumulate.signing.signer import Signer
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from eth_keys import keys as eth_keys
from eth_keys.exceptions import BadSignature
from cryptography.hazmat.primitives import serialization


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
    private_key, _ = generate_eth_keys()
    signature = {"type": SignatureType.ETH}
    signer.set_public_key(signature, private_key)
    assert "public_key" in signature


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
