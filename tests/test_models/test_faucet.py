# accumulate-python-client\tests\test_models\test_faucet.py

import pytest
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from accumulate.models.faucet import Faucet, FaucetSigner
from accumulate.models.signatures import (
    ED25519Signature,
    LegacyED25519Signature,
    RCD1Signature,
    Signature,
)
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.models.signature_types import SignatureType


def test_faucet_public_key():
    """Test the generation of the faucet's public key."""
    faucet = Faucet()
    expected_public_key = Faucet.FAUCET_KEY.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )
    assert faucet.public_key() == expected_public_key


def test_faucet_url_generation():
    """Test the generation of the faucet URL."""
    faucet = Faucet()
    public_key = faucet.public_key()
    expected_url = f"{LiteAuthorityForKey(public_key, SignatureType.ED25519)}/ACME"
    assert faucet.faucet_url == expected_url


def test_faucet_signer_creation():
    """Test the creation of a FaucetSigner."""
    faucet = Faucet()
    signer = faucet.signer()
    assert isinstance(signer, FaucetSigner)
    assert isinstance(signer.timestamp, int)
    assert signer.timestamp > 0


def test_faucet_signer_version():
    """Test the version of FaucetSigner."""
    signer = FaucetSigner(1234567890)
    assert signer.version() == 1


def test_faucet_signer_set_public_key():
    """Test setting the public key using FaucetSigner."""
    signer = FaucetSigner(1234567890)
    dummy_signer = None  # Replace with an actual signer URL if needed
    dummy_public_key = Faucet.FAUCET_KEY.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )
    dummy_signature = b"dummy_signature"
    dummy_timestamp = 1234567890
    dummy_transaction_data = b"dummy_transaction_data"

    # Valid signature types
    for sig_class in [ED25519Signature, LegacyED25519Signature, RCD1Signature]:
        if sig_class == ED25519Signature:
            sig = sig_class(dummy_signer, dummy_public_key, dummy_signature, dummy_transaction_data)
        else:
            sig = sig_class(dummy_signer, dummy_public_key, dummy_signature, dummy_timestamp)
        signer.set_public_key(sig)
        expected_key = Faucet.FAUCET_KEY.public_key().public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        )
        assert sig.public_key == expected_key

    # Unsupported signature type
    class UnsupportedSignature(Signature):
        def __init__(self):
            super().__init__(signature_type="Unsupported")

    sig = UnsupportedSignature()
    with pytest.raises(ValueError, match="Cannot set the public key on UnsupportedSignature"):
        signer.set_public_key(sig)


def test_faucet_signer_sign():
    """Test signing with the FaucetSigner."""
    signer = FaucetSigner(1234567890)
    message = b"Test message"
    sig_md_hash = hashlib.sha256(message).digest()
    dummy_signer = None  # Replace with an actual signer URL if needed
    dummy_public_key = Faucet.FAUCET_KEY.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )
    dummy_signature = b"dummy_signature"
    dummy_timestamp = 1234567890
    dummy_transaction_data = b"dummy_transaction_data"

    # Valid signature types
    for sig_class in [ED25519Signature, LegacyED25519Signature, RCD1Signature]:
        if sig_class == ED25519Signature:
            sig = sig_class(dummy_signer, dummy_public_key, dummy_signature, dummy_transaction_data)
        else:
            sig = sig_class(dummy_signer, dummy_public_key, dummy_signature, dummy_timestamp)
        signer.sign(sig, sig_md_hash, message)
        expected_signature = Faucet.FAUCET_KEY.sign(message)
        assert sig.signature == expected_signature

    # Unsupported signature type
    class UnsupportedSignature(Signature):
        def __init__(self):
            super().__init__(signature_type="Unsupported")

    sig = UnsupportedSignature()
    with pytest.raises(ValueError, match="Cannot sign UnsupportedSignature with a key."):
        signer.sign(sig, sig_md_hash, message)


def test_faucet_constants():
    """Test the constants defined in Faucet."""
    assert Faucet.ACME_FAUCET_AMOUNT == 10
    assert Faucet.ACME_FAUCET_BALANCE == 200_000_000

    expected_seed = hashlib.sha256(b"faucet").digest()
    assert Faucet.FAUCET_SEED == expected_seed

    expected_key = Ed25519PrivateKey.from_private_bytes(expected_seed[:32])
    assert Faucet.FAUCET_KEY.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,  # Private keys use PrivateFormat.PKCS8 in PEM encoding
        encryption_algorithm=NoEncryption(),
    ) == expected_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
