# accumulate-python-client\accumulate\utils\address_from.py

from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_keys import keys as eth_keys

from accumulate.models.signatures import PublicKey, PrivateKey
from accumulate.models.signature_types import SignatureType


def generate_ed25519_keypair():
    """Generate an Ed25519 keypair that matches TweetNaCl (64-byte private key, 32-byte public key)."""
    private_key = Ed25519PrivateKey.generate()

    # Extract private key bytes (32 bytes)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Extract public key bytes (32 bytes)
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Concatenate private key + public key to create a 64-byte private key
    private_key_64 = private_key_bytes + public_key_bytes

    return private_key_64, public_key_bytes


def from_ed25519_public_key(key: bytes) -> PublicKey:
    """Create a PublicKey instance from an Ed25519 public key (must be 32 bytes)."""
    if len(key) != 32:
        raise ValueError("Invalid Ed25519 public key length (must be 32 bytes).")
    return PublicKey(type_=SignatureType.ED25519, key=key)


def from_ed25519_private_key(key: bytes) -> PrivateKey:
    """Create a PrivateKey instance from an Ed25519 private key (must be 64 bytes)."""
    if len(key) == 32:
        private_key_bytes = key
    elif len(key) == 64:
        private_key_bytes = key[:32]  # Extract first 32 bytes as the actual private key
    else:
        raise ValueError("Invalid Ed25519 private key length (must be 32 or 64 bytes).")

    # Generate the public key from the extracted private key
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return PrivateKey(type_=SignatureType.ED25519, key=private_key_bytes, public_key=public_key_bytes)


def from_rsa_public_key(key: rsa.RSAPublicKey) -> PublicKey:
    """Create a PublicKey instance from an RSA public key."""
    key_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return PublicKey(type_=SignatureType.RSA_SHA256, key=key_bytes)


def from_rsa_private_key(key: rsa.RSAPrivateKey) -> PrivateKey:
    """Create a PrivateKey instance from an RSA private key."""
    private_key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = from_rsa_public_key(key.public_key())
    return PrivateKey(type_=SignatureType.RSA_SHA256, key=private_key_bytes, public_key=public_key.key)


def from_ecdsa_public_key(key: ec.EllipticCurvePublicKey) -> PublicKey:
    """Create a PublicKey instance from an ECDSA public key."""
    key_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return PublicKey(type_=SignatureType.ECDSA_SHA256, key=key_bytes)


def from_ecdsa_private_key(key: ec.EllipticCurvePrivateKey) -> PrivateKey:
    """Create a PrivateKey instance from an ECDSA private key."""
    private_key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = from_ecdsa_public_key(key.public_key())
    return PrivateKey(type_=SignatureType.ECDSA_SHA256, key=private_key_bytes, public_key=public_key.key)


def from_eth_private_key(key: bytes) -> PrivateKey:
    """Create a PrivateKey instance from an Ethereum private key."""
    eth_key = eth_keys.PrivateKey(key)
    public_key_bytes = eth_key.public_key.to_bytes()
    return PrivateKey(type_=SignatureType.ECDSA_SHA256, key=key, public_key=public_key_bytes)


def from_private_key_bytes(key: bytes, signature_type: SignatureType) -> PrivateKey:
    """Create a PrivateKey instance from raw private key bytes."""
    if signature_type == SignatureType.ED25519:
        if len(key) not in {32, 64}:
            raise ValueError("Ed25519 key must be 32 or 64 bytes.")
        return from_ed25519_private_key(key)
    
    elif signature_type == SignatureType.RSA_SHA256:
        private_key = serialization.load_pem_private_key(key, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Provided key is not an RSA private key.")
        return from_rsa_private_key(private_key)

    elif signature_type == SignatureType.ECDSA_SHA256:
        private_key = serialization.load_pem_private_key(key, password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Provided key is not an ECDSA private key.")
        return from_ecdsa_private_key(private_key)

    elif signature_type in {SignatureType.BTC, SignatureType.ETH, SignatureType.BTC_LEGACY}:
        return from_eth_private_key(key)

    else:
        raise ValueError(f"Unsupported signature type: {signature_type}")
