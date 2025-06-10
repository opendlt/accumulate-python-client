# accumulate-python-client\tests\test_utils\test_address_from.py

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from eth_keys import keys as eth_keys

from accumulate.utils.address_from import (
    generate_ed25519_keypair,
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

# Constants
VALID_ED25519_PUBLIC_KEY = b"\x01" * 32
VALID_ED25519_PRIVATE_KEY_64 = b"\x02" * 32 + b"\x03" * 32
VALID_ED25519_PRIVATE_KEY_32 = b"\x04" * 32
INVALID_KEY = b"\x01" * 16

@pytest.fixture
def rsa_priv():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

@pytest.fixture
def ecdsa_priv():
    return ec.generate_private_key(ec.SECP256R1())


# --- generate_ed25519_keypair ---
def test_generate_ed25519_keypair_lengths_and_consistency():
    priv64, pub32 = generate_ed25519_keypair()
    assert isinstance(priv64, bytes) and isinstance(pub32, bytes)
    assert len(priv64) == 64
    assert len(pub32) == 32
    # trailing half of priv64 must equal pub32
    assert priv64[32:] == pub32


# --- Ed25519 public key ---
def test_from_ed25519_public_key_valid():
    pk = from_ed25519_public_key(VALID_ED25519_PUBLIC_KEY)
    assert isinstance(pk, PublicKey)
    assert pk.type == SignatureType.ED25519
    assert pk.key == VALID_ED25519_PUBLIC_KEY

def test_from_ed25519_public_key_invalid_length_exact_msg():
    with pytest.raises(ValueError) as exc:
        from_ed25519_public_key(INVALID_KEY)
    assert str(exc.value) == "Invalid Ed25519 public key length (must be 32 bytes)."


# --- Ed25519 private key ---
def test_from_ed25519_private_key_64_bytes():
    sk = from_ed25519_private_key(VALID_ED25519_PRIVATE_KEY_64)
    assert isinstance(sk, PrivateKey)
    assert sk.type == SignatureType.ED25519
    # key stored is first 32 bytes
    assert sk.key == VALID_ED25519_PRIVATE_KEY_64[:32]
    # derived public matches
    priv = Ed25519PrivateKey.from_private_bytes(sk.key)
    expected_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert sk.public_key.key == expected_pub

def test_from_ed25519_private_key_32_bytes():
    sk = from_ed25519_private_key(VALID_ED25519_PRIVATE_KEY_32)
    assert isinstance(sk, PrivateKey) and sk.type == SignatureType.ED25519
    assert sk.key == VALID_ED25519_PRIVATE_KEY_32

def test_from_ed25519_private_key_invalid_length():
    with pytest.raises(ValueError, match="Invalid Ed25519 private key length"):
        from_ed25519_private_key(INVALID_KEY)


# --- RSA keys ---
def test_from_rsa_public_key(rsa_priv):
    pub = rsa_priv.public_key()
    out = from_rsa_public_key(pub)
    assert isinstance(out, PublicKey)
    assert out.type == SignatureType.RSA_SHA256
    assert b"BEGIN PUBLIC KEY" in out.key

def test_from_rsa_private_key(rsa_priv):
    sk = from_rsa_private_key(rsa_priv)
    assert isinstance(sk, PrivateKey)
    assert sk.type == SignatureType.RSA_SHA256
    assert b"BEGIN PRIVATE KEY" in sk.key
    # public_key is a PublicKey model, whose .key holds the PEM bytes
    from accumulate.models.signatures import PublicKey
    assert isinstance(sk.public_key, PublicKey)
    assert b"BEGIN PUBLIC KEY" in sk.public_key.key


# --- ECDSA keys ---
def test_from_ecdsa_public_key(ecdsa_priv):
    pub = ecdsa_priv.public_key()
    out = from_ecdsa_public_key(pub)
    assert isinstance(out, PublicKey)
    assert out.type == SignatureType.ECDSA_SHA256
    assert b"BEGIN PUBLIC KEY" in out.key

def test_from_ecdsa_private_key(ecdsa_priv):
    sk = from_ecdsa_private_key(ecdsa_priv)
    assert isinstance(sk, PrivateKey)
    assert sk.type == SignatureType.ECDSA_SHA256
    assert b"BEGIN PRIVATE KEY" in sk.key
    from accumulate.models.signatures import PublicKey
    assert isinstance(sk.public_key, PublicKey)
    assert b"BEGIN PUBLIC KEY" in sk.public_key.key


# --- Ethereum key ---
def test_from_eth_private_key():
    raw = b"\x01" * 32
    sk = from_eth_private_key(raw)
    assert isinstance(sk, PrivateKey)
    assert sk.type == SignatureType.ECDSA_SHA256
    assert sk.key == raw
    # public_key is a PublicKey model; its .key is the raw bytes
    eth_pk = eth_keys.PrivateKey(raw).public_key.to_bytes()
    from accumulate.models.signatures import PublicKey
    assert isinstance(sk.public_key, PublicKey)
    assert sk.public_key.key == eth_pk


# --- from_private_key_bytes generic ---
def test_from_private_key_bytes_ed25519():
    sk = from_private_key_bytes(VALID_ED25519_PRIVATE_KEY_32, SignatureType.ED25519)
    assert isinstance(sk, PrivateKey) and sk.type == SignatureType.ED25519

def test_from_private_key_bytes_rsa_and_invalid(rsa_priv):
    # valid PEM
    pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sk = from_private_key_bytes(pem, SignatureType.RSA_SHA256)
    assert isinstance(sk, PrivateKey) and sk.type == SignatureType.RSA_SHA256

    # invalid RSA
    with pytest.raises(ValueError, match="Could not deserialize key data."):
        from_private_key_bytes(b"not-pem", SignatureType.RSA_SHA256)

def test_from_private_key_bytes_ecdsa_and_invalid(ecdsa_priv):
    pem = ecdsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sk = from_private_key_bytes(pem, SignatureType.ECDSA_SHA256)
    assert isinstance(sk, PrivateKey) and sk.type == SignatureType.ECDSA_SHA256

    with pytest.raises(ValueError, match="Could not deserialize key data."):
        from_private_key_bytes(b"not-pem", SignatureType.ECDSA_SHA256)

def test_from_private_key_bytes_eth_and_btc():
    raw = b"\x02" * 32
    for sig in (SignatureType.ETH, SignatureType.BTC, SignatureType.BTC_LEGACY):
        sk = from_private_key_bytes(raw, sig)
        assert isinstance(sk, PrivateKey)
        assert sk.type == SignatureType.ECDSA_SHA256

def test_from_private_key_bytes_unsupported():
    with pytest.raises(ValueError, match="Unsupported signature type"):
        from_private_key_bytes(b"\x00"*32, "NOT_A_TYPE")

