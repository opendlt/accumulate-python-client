# accumulate-python-client\tests\test_signing\test_signature_handler.py 

import pytest
import hashlib
from unittest.mock import Mock, MagicMock
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec, padding
from accumulate.signing.signature_handler import SignatureHandler
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from eth_keys import keys as eth_keys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from accumulate.models.signatures import Signature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

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

##########################
##########################
##########################

@pytest.fixture
def delegator_url():
    """Fixture to provide a sample delegator URL."""
    return URL("acc://example.delegator")

@pytest.fixture
def origin_url():
    """Fixture to provide a sample origin URL."""
    return URL("acc://example.origin")

@pytest.fixture
def authority_url():
    """Fixture to provide a sample authority URL."""
    return URL("acc://example.authority")

def test_btc_address():
    """Test generating a BTC address."""
    public_key = b"\x02" * 33
    result = SignatureHandler.btc_address(public_key)
    assert isinstance(result, str)

def test_eth_address():
    """Test generating an ETH address."""
    public_key = b"\x04" + b"\x02" * 64
    result = SignatureHandler.eth_address(public_key)
    assert isinstance(result, str)
    assert result.startswith("0x")

def test_sign_rsa_sha256():
    """Test signing with RSA SHA256."""
    # Generate a private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Message to be signed
    message = b"test_message"
    # Call the sign_rsa_sha256 method
    result = SignatureHandler.sign_rsa_sha256(private_key_bytes, message)
    # Assert the result is a byte object (signature)
    assert isinstance(result, bytes)


def test_verify_rsa_sha256():
    """Test verifying an RSA SHA256 signature."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    message = b"test_message"

    # Generate signature using the updated signing method
    signature = SignatureHandler.sign_rsa_sha256(private_key_bytes, message)

    # Verify the signature using the updated verification method
    assert SignatureHandler.verify_rsa_sha256(public_key_bytes, message, signature) is True



def test_sign_btc():
    """Test signing with BTC."""
    private_key = b"\x01" * 32
    message = b"test_message"
    result = SignatureHandler.sign_btc(private_key, message)
    assert isinstance(result, bytes)

def test_verify_btc():
    """Test verifying a BTC signature."""
    private_key = b"\x01" * 32
    message = b"test_message"
    priv_key_obj = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
    public_key = priv_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    signature = priv_key_obj.sign(message, ec.ECDSA(SHA256()))
    assert SignatureHandler.verify_btc(public_key, message, signature)

def test_sign_eth():
    """Test signing with ETH."""
    private_key = b"\x01" * 32
    message_hash = hashlib.sha256(b"test_message").digest()
    result = SignatureHandler.sign_eth(private_key, message_hash)
    assert isinstance(result, bytes)

def test_verify_eth():
    """Test verifying an ETH signature."""
    private_key = b"\x01" * 32
    eth_key = eth_keys.PrivateKey(private_key)
    public_key = eth_key.public_key.to_bytes()
    message_hash = hashlib.sha256(b"test_message").digest()
    signature = eth_key.sign_msg_hash(message_hash).to_bytes()
    assert SignatureHandler.verify_eth(public_key, message_hash, signature)

def test_sign_ecdsa_sha256():
    """Test signing with ECDSA SHA256."""
    private_key = b"\x01" * 32
    message = b"test_message"
    result = SignatureHandler.sign_ecdsa_sha256(private_key, message)
    assert isinstance(result, bytes)

def test_verify_ecdsa_sha256():
    """Test verifying an ECDSA SHA256 signature."""
    private_key = b"\x01" * 32
    message = b"test_message"
    priv_key_obj = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
    public_key = priv_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    signature = priv_key_obj.sign(message, ec.ECDSA(SHA256()))
    assert SignatureHandler.verify_ecdsa_sha256(public_key, message, signature)

def test_sign_delegated_signature(delegator_url):
    """Test signing a delegated signature."""
    inner_signature = b"test_inner_signature"
    result = SignatureHandler.sign_delegated_signature(inner_signature, delegator_url)
    expected_hash = hashlib.sha256(inner_signature + str(delegator_url).encode()).digest()
    assert result == expected_hash

def test_verify_delegated_signature_valid(delegator_url):
    """Test verifying a valid delegated signature."""
    inner_signature = b"test_inner_signature"
    expected_signature = SignatureHandler.sign_delegated_signature(inner_signature, delegator_url)
    assert SignatureHandler.verify_delegated_signature(expected_signature, inner_signature, delegator_url)



def test_verify_merkle_hash():
    """Test verifying a Merkle hash."""
    metadata_hash = hashlib.sha256(b"metadata").digest()
    txn_hash = hashlib.sha256(b"transaction").digest()

    # Mock the Signature object with a transaction_hash attribute
    signature = MagicMock()
    signature.transaction_hash = hashlib.sha256(metadata_hash + txn_hash).digest()

    # Test the verify_merkle_hash method
    assert SignatureHandler.verify_merkle_hash(metadata_hash, txn_hash, signature)

def test_sign_authority_signature(origin_url, authority_url):
    """Test signing an authority signature."""
    vote = "approve"
    txid = "12345"
    result = SignatureHandler.sign_authority_signature(origin_url, authority_url, vote, txid)
    expected_hash = hashlib.sha256(
        str(origin_url).encode()
        + str(authority_url).encode()
        + vote.encode()
        + txid.encode()
    ).digest()
    assert result == expected_hash


def test_verify_authority_signature_valid(origin_url, authority_url):
    """Test verifying a valid authority signature."""
    vote = "approve"
    txid = "12345"
    signature = SignatureHandler.sign_authority_signature(origin_url, authority_url, vote, txid)
    assert SignatureHandler.verify_authority_signature(signature, origin_url, authority_url, vote, txid) is True



###########

def test_create_authority_signature():
    """Test creating an authority signature."""
    # Use actual URL instances instead of mocks
    origin = URL(authority="origin")
    authority = URL(authority="authority")
    
    # Call the method to create the authority signature
    result = SignatureHandler.create_authority_signature(origin, authority, "vote", "txid")
    
    # Calculate the expected hash
    expected = hashlib.sha256(b"originauthorityvotetxid").digest()
    
    # Assert the result matches the expected hash
    assert result == expected



def test_verify_authority_signature_valid(origin_url, authority_url):
    """Test verifying a valid authority signature."""
    vote = "approve"
    txid = "12345"
    signature = SignatureHandler.sign_authority_signature(origin_url, authority_url, vote, txid)
    assert SignatureHandler.verify_authority_signature(signature, origin_url, authority_url, vote, txid) is True


def test_verify_authority_signature_invalid(origin_url, authority_url):
    """Test verifying an invalid authority signature."""
    vote = "approve"
    txid = "12345"
    signature = b"invalid"
    assert not SignatureHandler.verify_authority_signature(signature, origin_url, authority_url, vote, txid)



def test_sign_delegated_signature():
    """Test signing a delegated signature."""
    inner_signature = b"test_inner_signature"
    # Create an actual URL instance
    delegator = URL(authority="example.delegator")
    # Use the method to sign the delegated signature
    result = SignatureHandler.sign_delegated_signature(inner_signature, delegator)
    # Calculate the expected hash
    expected_hash = hashlib.sha256(inner_signature + str(delegator).encode()).digest()
    # Assert that the result matches the expected hash
    assert result == expected_hash

def test_verify_delegated_signature_valid(delegator_url):
    """Test verifying a valid delegated signature."""
    inner_signature = b"test_inner_signature"
    expected_signature = SignatureHandler.sign_delegated_signature(inner_signature, delegator_url)
    assert SignatureHandler.verify_delegated_signature(expected_signature, inner_signature, delegator_url)

def test_verify_delegated_signature_invalid(delegator_url):
    """Test verifying an invalid delegated signature."""
    inner_signature = b"test_inner_signature"
    assert not SignatureHandler.verify_delegated_signature(b"invalid", inner_signature, delegator_url)