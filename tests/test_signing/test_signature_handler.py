# C:\Accumulate_Stuff\accumulate-python-client\tests\test_signing\test_signature_handler.py 

import pytest
import hashlib
from unittest.mock import Mock
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from accumulate.signing.signature_handler import SignatureHandler
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from eth_keys import keys as eth_keys
from cryptography.hazmat.primitives import serialization


# Helper Functions
def generate_ed25519_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def generate_eth_keys():
    private_key = eth_keys.PrivateKey(hashlib.sha256(b"test_key").digest())
    return private_key.to_bytes(), private_key.public_key.to_bytes()


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


# Test Cases
def test_sign_delegated_signature():
    inner_signature = b"inner_sig"
    delegator = Mock()
    delegator.to_string.return_value = "delegator_url"
    result = SignatureHandler.sign_delegated_signature(inner_signature, delegator)
    expected = hashlib.sha256(inner_signature + b"delegator_url").digest()
    assert result == expected


def test_verify_delegated_signature_valid():
    inner_signature = b"inner_sig"
    delegator = Mock()
    delegator.to_string.return_value = "delegator_url"
    delegated_signature = hashlib.sha256(inner_signature + b"delegator_url").digest()
    assert SignatureHandler.verify_delegated_signature(delegated_signature, inner_signature, delegator) is True


def test_verify_delegated_signature_invalid():
    inner_signature = b"inner_sig"
    delegator = Mock()
    delegator.to_string.return_value = "delegator_url"
    assert not SignatureHandler.verify_delegated_signature(b"invalid", inner_signature, delegator)


def test_sign_ed25519():
    private_key, _ = generate_ed25519_keys()
    message = b"Test Message"
    signature = SignatureHandler.sign_ed25519(private_key, message)
    assert isinstance(signature, bytes)


def test_verify_ed25519_valid():
    private_key, public_key = generate_ed25519_keys()
    message = b"Test Message"
    signature = SignatureHandler.sign_ed25519(private_key, message)
    assert SignatureHandler.verify_ed25519(public_key, message, signature) is True


def test_verify_ed25519_invalid():
    _, public_key = generate_ed25519_keys()
    message = b"Test Message"
    signature = b"invalid"
    assert not SignatureHandler.verify_ed25519(public_key, message, signature)


def test_sign_eth():
    private_key, _ = generate_eth_keys()
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = SignatureHandler.sign_eth(private_key, message_hash)
    assert isinstance(signature, bytes)


def test_verify_eth_valid():
    private_key, public_key = generate_eth_keys()
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = SignatureHandler.sign_eth(private_key, message_hash)
    assert SignatureHandler.verify_eth(public_key, message_hash, signature) is True


def test_verify_eth_invalid():
    _, public_key = generate_eth_keys()
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = b"invalid"  # Invalid signature of incorrect length
    assert not SignatureHandler.verify_eth(public_key, message_hash, signature)


def test_create_authority_signature():
    origin = Mock()
    origin.to_string.return_value = "origin"
    authority = Mock()
    authority.to_string.return_value = "authority"
    result = SignatureHandler.create_authority_signature(origin, authority, "vote", "txid")
    expected = hashlib.sha256(b"originauthorityvotetxid").digest()
    assert result == expected


def test_verify_authority_signature_valid():
    origin = Mock()
    origin.to_string.return_value = "origin"
    authority = Mock()
    authority.to_string.return_value = "authority"
    signature = hashlib.sha256(b"originauthorityvotetxid").digest()
    assert SignatureHandler.verify_authority_signature(signature, origin, authority, "vote", "txid") is True


def test_verify_authority_signature_invalid():
    origin = Mock()
    origin.to_string.return_value = "origin"
    authority = Mock()
    authority.to_string.return_value = "authority"
    signature = b"invalid"
    assert not SignatureHandler.verify_authority_signature(signature, origin, authority, "vote", "txid")
