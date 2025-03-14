# accumulate-python-client\tests\test_signing\test_builder.py 

import pytest
from unittest.mock import Mock
from datetime import datetime

@pytest.fixture
def builder():
    """Lazy import Builder to prevent circular imports."""
    from accumulate.signing.builder import Builder  # Move import here
    return Builder()

def test_set_type(builder):
    from accumulate.models.signature_types import SignatureType  # Lazy import
    builder.set_type(SignatureType.ED25519)
    assert builder.type == SignatureType.ED25519

def test_set_url_valid(builder):
    from accumulate.utils.url import URL  # Lazy import
    valid_url = URL.parse("acc://example.acme")
    builder.set_url(valid_url)
    assert builder.url == valid_url
    # Expect the full prefix
    assert str(builder.url) == "acc://example.acme"

def test_set_url_invalid(builder):
    with pytest.raises(ValueError, match="Invalid Accumulate URL"):
        builder.set_url("invalid-url")

def test_set_url_reserved(builder):
    from accumulate.utils.url import URL  # Lazy import
    with pytest.raises(ValueError, match="Reserved URL cannot be used as a signer URL"):
        builder.set_url(URL.parse("acc://unknown"))

def test_set_signer(builder):
    from accumulate.signing.signer import Signer
    from accumulate.utils.url import URL
    dummy_signer = Signer(url=URL.parse("acc://example.acme"))
    builder.set_signer(dummy_signer)
    assert builder.signer == dummy_signer

def test_set_version(builder):
    builder.set_version(1)
    assert builder.version == 1

def test_set_timestamp(builder):
    builder.set_timestamp(1234567890)
    assert builder.timestamp == 1234567890

def test_set_timestamp_to_now(builder):
    builder.set_timestamp_to_now()
    assert builder.timestamp is not None
    assert isinstance(builder.timestamp, int)

def test_set_memo(builder):
    builder.set_memo("Test memo")
    assert builder.memo == "Test memo"

def test_set_data(builder):
    builder.set_data(b"Test data")
    assert builder.data == b"Test data"

def test_add_delegator_valid(builder):
    from accumulate.utils.url import URL  # Lazy import
    valid_delegator = URL.parse("acc://example.acme/delegator")
    builder.add_delegator(valid_delegator)
    assert builder.delegators == [valid_delegator]
    assert str(builder.delegators[0]) == "acc://example.acme/delegator"

def test_add_delegator_invalid(builder):
    with pytest.raises(ValueError, match="Invalid delegator URL"):
        builder.add_delegator("invalid-url")

def test_validate_signature_requirements_missing_url(builder):
    with pytest.raises(ValueError, match="Missing signer URL"):
        builder._validate_signature_requirements(init=True)

def test_validate_signature_requirements_missing_signer(builder):
    from accumulate.utils.url import URL  # Lazy import
    builder.set_url(URL.parse("acc://example.acme"))
    with pytest.raises(ValueError, match="Missing signer"):
        builder._validate_signature_requirements(init=True)

def test_create_signature_valid(builder):
    from accumulate.models.signature_types import SignatureType  # Lazy import
    from accumulate.models.signatures import ED25519Signature  # Lazy import
    from accumulate.utils.url import URL  # Lazy import
    from accumulate.signing.signer import Signer
    # Create a dummy Signer with valid URL and dummy get_public_key
    dummy_signer = Signer(url=URL.parse("acc://example.acme"))
    dummy_signer.get_public_key = lambda: b"mock_public_key"
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(dummy_signer)
    # Pass some dummy transaction data
    signature = builder._create_signature(b"dummy_tx_data")
    assert isinstance(signature, ED25519Signature)
    # Expect the signer (i.e. builder.url) to print with its full prefix
    assert str(signature.signer) == "acc://example.acme"
    assert signature.signerVersion == builder.version
    assert signature.timestamp == builder.timestamp
    # Use the correct attribute name from the signature model
    assert signature.publicKey == b"mock_public_key"

def test_prepare_valid(builder):
    from accumulate.models.signature_types import SignatureType  # Lazy import
    from accumulate.models.signatures import ED25519Signature  # Lazy import
    from accumulate.utils.url import URL  # Lazy import
    from accumulate.signing.signer import Signer
    dummy_signer = Signer(url=URL.parse("acc://example.acme"))
    dummy_signer.get_public_key = lambda: b"mock_public_key"
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(dummy_signer)
    signature = builder.prepare(init=True, transaction_data=b"mock_data")
    assert isinstance(signature, ED25519Signature)
    assert str(signature.signer) == "acc://example.acme"

@pytest.mark.asyncio
async def test_sign_valid(builder):
    from accumulate.models.signature_types import SignatureType  # Lazy import
    from accumulate.utils.url import URL  # Lazy import
    from accumulate.utils.hash_functions import hash_data  # Lazy import
    from accumulate.signing.signer import Signer
    dummy_signer = Signer(url=URL.parse("acc://example.acme"))
    # Updated dummy function to include "signer"
    async def dummy_sign_transaction(sig_type, msg, txn_header=None, signer_version=None):
        return {
            "signature": b"deadbeef",
            "signerVersion": 1,
            "transactionHash": hash_data(msg).hex(),
            "signer": str(dummy_signer.url)
        }
    dummy_signer.get_public_key = lambda: b"mock_public_key"
    dummy_signer.sign_transaction = dummy_sign_transaction
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(dummy_signer)
    message = b"Test message"
    signature = await builder.sign(message)
    assert signature["transactionHash"] == hash_data(message).hex()
    assert signature["signer"] == "acc://example.acme"


@pytest.mark.asyncio
async def test_initiate_valid(builder):
    from accumulate.models.signature_types import SignatureType  # Lazy import
    from accumulate.utils.url import URL  # Lazy import
    from accumulate.signing.signer import Signer
    dummy_signer = Signer(url=URL.parse("acc://example.acme"))
    dummy_signer.get_public_key = lambda: b"mock_public_key"
    # Adjust dummy_sign_transaction to allow txn_header to be optional.
    async def dummy_sign_transaction(sig_type, msg, txn_header=None, signer_version=None):
        return {"signature": b"deadbeef", "signerVersion": 1}
    dummy_signer.sign_transaction = dummy_sign_transaction
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(dummy_signer)
    txn = Mock()
    txn.get_hash.return_value = b"txn_hash"
    txn.header = Mock()
    txn.header.timestamp = 1234567890
    signature = await builder.initiate(txn)
    assert signature.transactionHash == b"txn_hash"
    assert str(signature.signer) == "acc://example.acme"
