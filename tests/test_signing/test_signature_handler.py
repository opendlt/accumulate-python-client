# accumulate-python-client\tests\test_signing\test_signature_handler.py 

from accumulate.utils.validation import ValidationError
import pytest
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock, MagicMock, patch
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
from eth_keys.exceptions import BadSignature



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

    # Mock the Signature object with a transactionHash attribute (camelCase)
    signature = MagicMock()
    signature.transactionHash = hashlib.sha256(metadata_hash + txn_hash).digest()

    # Test the verify_merkle_hash method
    assert SignatureHandler.verify_merkle_hash(metadata_hash, txn_hash, signature)


def test_sign_authority_signature(origin_url, authority_url):
    """Test signing an authority signature."""
    vote = "approve"
    txid = "12345"
    result = SignatureHandler.create_authority_signature(origin_url, authority_url, vote, txid)
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

def test_create_authority_signature():
    """Test creating an authority signature."""
    # Use actual URL instances instead of mocks
    origin = URL(authority="origin")
    authority = URL(authority="authority")

    # Call the method to create the authority signature
    result = SignatureHandler.create_authority_signature(origin, authority, "vote", "txid")

    # Calculate the expected hash using the actual string representations of the URLs
    expected = hashlib.sha256(
        str(origin).encode() + str(authority).encode() + b"vote" + b"txid"
    ).digest()

    # Assert the result matches the expected hash
    assert result == expected


def test_verify_authority_signature_valid(origin_url, authority_url):
    """Test verifying a valid authority signature."""
    vote = "approve"
    txid = "12345"
    signature = SignatureHandler.create_authority_signature(origin_url, authority_url, vote, txid)
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

def test_verify_eth_valid_signature():
    """Test verifying a valid Ethereum signature."""
    # Generate Ethereum keys
    private_key, public_key = generate_eth_keys()
    message_hash = hashlib.sha256(b"test_message").digest()

    # Sign the message hash
    signature = SignatureHandler.sign_eth(private_key, message_hash)

    # Verify the signature
    assert SignatureHandler.verify_eth(public_key, message_hash, signature) is True

def test_verify_eth_invalid_signature_length():
    """Test verifying an Ethereum signature with an invalid length."""
    _, public_key = generate_eth_keys()
    message_hash = hashlib.sha256(b"test_message").digest()
    
    # Invalid signature length
    invalid_signature = b"\x00" * 63  # ETH signature length must be 65 bytes
    assert not SignatureHandler.verify_eth(public_key, message_hash, invalid_signature)


def test_verify_eth_invalid_signature_content():
    """Test verifying an Ethereum signature with invalid content."""
    private_key, public_key = generate_eth_keys()
    message_hash = hashlib.sha256(b"test_message").digest()

    # Sign the message hash
    valid_signature = SignatureHandler.sign_eth(private_key, message_hash)

    # Tamper with the valid signature by flipping a bit in the middle
    tampered_signature = bytearray(valid_signature)
    tampered_signature[len(tampered_signature) // 2] ^= 0xFF  # flip a bit in the middle
    tampered_signature = bytes(tampered_signature)

    # Debugging output
    print(f"DEBUG: Valid signature: {valid_signature}")
    print(f"DEBUG: Tampered signature: {tampered_signature}")
    print(f"DEBUG: Public key: {public_key}")
    print(f"DEBUG: Message hash: {message_hash}")

    # Verify tampered signature
    result = SignatureHandler.verify_eth(public_key, message_hash, tampered_signature)
    print(f"DEBUG: Verification result for tampered signature: {result}")

    # Verify the tampered signature fails
    assert not result

def test_verify_eth_invalid_public_key():
    """Test verifying an Ethereum signature with an invalid public key."""
    _, public_key = generate_eth_keys()
    invalid_public_key = b"\x01" * len(public_key)  # Invalid public key
    message_hash = hashlib.sha256(b"test_message").digest()

    # Sign the message hash
    private_key, _ = generate_eth_keys()
    signature = SignatureHandler.sign_eth(private_key, message_hash)

    # Verify the signature with an invalid public key
    assert not SignatureHandler.verify_eth(invalid_public_key, message_hash, signature)


def test_verify_eth_invalid_message_hash():
    """Test verifying an Ethereum signature with an invalid message hash."""
    private_key, public_key = generate_eth_keys()
    valid_message_hash = hashlib.sha256(b"test_message").digest()

    # Sign the valid message hash
    signature = SignatureHandler.sign_eth(private_key, valid_message_hash)

    # Use a different message hash for verification
    invalid_message_hash = hashlib.sha256(b"invalid_message").digest()
    assert not SignatureHandler.verify_eth(public_key, invalid_message_hash, signature)

# Test `sign_eth` Method Call
def test_sign_eth_method_call():
    """Test that `sign_typed_data` correctly calls `sign_eth`."""
    private_key = hashlib.sha256(b"test_key").digest()
    message_hash = hashlib.sha256(b"Test Message").digest()

    with patch.object(SignatureHandler, "sign_eth", return_value=b"mock_signature") as mock_sign:
        signature = SignatureHandler.sign_typed_data(private_key, message_hash)
    
        # Ensure the method was called
        mock_sign.assert_called_once_with(private_key, message_hash)
        assert signature == b"mock_signature"


def test_verify_eth_validation_error():
    from eth_utils.exceptions import ValidationError as EthValidationError
    """Test that `verify_eth` handles `ValidationError` properly."""
    public_key = b"\x01" * 64  # Dummy public key
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = b"\x02" * 65  # Incorrect signature format

    with patch("accumulate.signing.signature_handler.eth_keys.PublicKey", side_effect=EthValidationError("Invalid key")):
        assert not SignatureHandler.verify_eth(public_key, message_hash, signature)


# Test `verify_eth` with `BadSignature`
def test_verify_eth_bad_signature():
    """Test that `verify_eth` handles `BadSignature` properly."""
    public_key = b"\x01" * 64  # Dummy public key
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = b"\x02" * 65  # Incorrect signature format

    with patch("accumulate.signing.signature_handler.eth_keys.Signature.recover_public_key_from_msg_hash", side_effect=BadSignature):
        assert not SignatureHandler.verify_eth(public_key, message_hash, signature)


# Test `verify_eth` with Unexpected Exception
def test_verify_eth_unexpected_exception():
    """Test that `verify_eth` handles unexpected exceptions properly."""
    public_key = b"\x01" * 64  # Dummy public key
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = b"\x02" * 65  # Incorrect signature format

    with patch("accumulate.signing.signature_handler.eth_keys.Signature.recover_public_key_from_msg_hash", side_effect=Exception("Unexpected Error")):
        assert not SignatureHandler.verify_eth(public_key, message_hash, signature)


# Test `verify_rsa_sha256` with Exception
def test_verify_rsa_sha256_exception():
    """Test that `verify_rsa_sha256` returns False on an unexpected exception."""
    public_key_pem = b"-----BEGIN PUBLIC KEY-----\nINVALID_KEY\n-----END PUBLIC KEY-----"
    message = b"Test Message"
    signature = b"invalid_signature"

    # Mock the RSA key loading to raise an exception
    with patch("cryptography.hazmat.primitives.serialization.load_pem_public_key", side_effect=Exception("Unexpected Error")):
        assert not SignatureHandler.verify_rsa_sha256(public_key_pem, message, signature)

# Test `verify_ecdsa_sha256` with Exception
def test_verify_ecdsa_sha256_exception():
    """Test that `verify_ecdsa_sha256` returns False on an unexpected exception."""
    public_key = b"\x01" * 33  # Incorrect ECDSA public key length
    message = b"Test Message"
    signature = b"invalid_signature"

    # Mock the ECDSA key parsing to raise an exception
    with patch("cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point", side_effect=Exception("Unexpected Error")):
        assert not SignatureHandler.verify_ecdsa_sha256(public_key, message, signature)

# Test: Valid Ethereum Signature (Covers Successful Execution Path)
def test_verify_eth_valid_signature2():
    """Test that `verify_eth` correctly verifies a valid Ethereum signature."""
    private_key = eth_keys.PrivateKey(hashlib.sha256(b"test_key").digest())
    public_key = private_key.public_key.to_bytes()
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = private_key.sign_msg_hash(message_hash).to_bytes()

    assert SignatureHandler.verify_eth(public_key, message_hash, signature) is True

# Test: Invalid Signature Length (Covers `except ValidationError`)
def test_verify_eth_invalid_signature_length2():
    """Test that `verify_eth` returns False for an invalid signature length."""
    public_key = eth_keys.PrivateKey(hashlib.sha256(b"test_key").digest()).public_key.to_bytes()
    message_hash = hashlib.sha256(b"Test Message").digest()
    invalid_signature = b"\x00" * 64  # Ethereum signatures must be 65 bytes

    assert SignatureHandler.verify_eth(public_key, message_hash, invalid_signature) is False

# Test: Bad Signature Content (Covers `except BadSignature`)
def test_verify_eth_bad_signature2():
    """Test that `verify_eth` returns False when signature content is invalid."""
    public_key = eth_keys.PrivateKey(hashlib.sha256(b"test_key").digest()).public_key.to_bytes()
    message_hash = hashlib.sha256(b"Test Message").digest()
    bad_signature = b"\x00" * 65  # Random invalid signature

    assert SignatureHandler.verify_eth(public_key, message_hash, bad_signature) is False

# Test: Exception Raised (Covers Any Unexpected Exceptions)
def test_verify_eth_unexpected_exception2():
    """Test that `verify_eth` safely handles unexpected exceptions."""
    public_key = eth_keys.PrivateKey(hashlib.sha256(b"test_key").digest()).public_key.to_bytes()
    message_hash = hashlib.sha256(b"Test Message").digest()
    signature = b"\x00" * 65  # Invalid Ethereum signature

    #  Correctly mock `eth_keys.datatypes.Signature` instead of `eth_keys.Signature`
    with patch("eth_keys.datatypes.Signature", side_effect=Exception("Unexpected Error")):
        assert SignatureHandler.verify_eth(public_key, message_hash, signature) is False

def test_verify_merkle_hash_exception_path():
    # Force an exception in metadata_hash + txn_hash (None + bytes → TypeError)
    bad_sig = SimpleNamespace(transactionHash=b'whatever')
    assert SignatureHandler.verify_merkle_hash(None, b'', bad_sig) is False

def test_verify_btc_exception_path():
    # Use a malformed public key so from_encoded_point raises
    bad_pub = b'\x00'*10
    bad_sig  = b'invalid'
    assert SignatureHandler.verify_btc(bad_pub, b'msg', bad_sig) is False

def test_sign_eth_exception_path():
    # Private key must be 32 bytes; anything else will make eth_keys.PrivateKey() blow up
    with pytest.raises(ValueError, match="Failed to sign Ethereum message"):
        SignatureHandler.sign_eth(b'\x01'*31, hashlib.sha256(b"x").digest())

def test_verify_signature_with_timestamp_unsupported_type():
    # Pick a type not in the verification_methods map (e.g. RCD1)
    sig = SimpleNamespace(signature=b'')
    with pytest.raises(ValueError, match=r"Unsupported signature type: .*RCD1"):
        SignatureHandler.verify_signature_with_timestamp(
            b'\x00', b'data', sig, SignatureType.RCD1
        )
