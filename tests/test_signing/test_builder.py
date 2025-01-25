# C:\Accumulate_Stuff\accumulate-python-client\tests\test_signing\test_builder.py 

import pytest
from unittest.mock import Mock
from datetime import datetime
from accumulate.signing.builder import Builder, InitHashMode
from accumulate.models.signature_types import SignatureType
from accumulate.models.signatures import ED25519Signature
from accumulate.models.transactions import Transaction
from accumulate.utils.url import URL
from accumulate.utils.hash_functions import hash_data

@pytest.fixture
def builder():
    """Fixture to provide a fresh Builder instance for each test."""
    return Builder()


def test_set_type(builder):
    builder.set_type(SignatureType.ED25519)
    assert builder.type == SignatureType.ED25519


def test_set_url_valid(builder):
    valid_url = URL.parse("acc://example.acme")
    builder.set_url(valid_url)
    # Check the builder's URL without expecting "acc://" in the string representation
    assert builder.url == valid_url
    assert str(builder.url) == "example.acme"



def test_set_url_invalid(builder):
    invalid_url = "invalid-url"
    with pytest.raises(ValueError, match="Invalid Accumulate URL"):
        builder.set_url(invalid_url)


def test_set_url_reserved(builder):
    reserved_url = URL.parse("acc://unknown")
    with pytest.raises(ValueError, match="Reserved URL cannot be used as a signer URL"):
        builder.set_url(reserved_url)


def test_set_signer(builder):
    signer = Mock()
    builder.set_signer(signer)
    assert builder.signer == signer


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
    valid_delegator = URL.parse("acc://example.acme/delegator")
    builder.add_delegator(valid_delegator)
    # Check delegators list without expecting "acc://" in the string representation
    assert builder.delegators == [valid_delegator]
    assert str(builder.delegators[0]) == "example.acme/delegator"


def test_add_delegator_invalid(builder):
    invalid_delegator = "invalid-url"
    with pytest.raises(ValueError, match="Invalid delegator URL"):
        builder.add_delegator(invalid_delegator)


def test_validate_signature_requirements_missing_url(builder):
    with pytest.raises(ValueError, match="Missing signer URL"):
        builder._validate_signature_requirements(init=True)


def test_validate_signature_requirements_missing_signer(builder):
    builder.set_url(URL.parse("acc://example.acme"))
    with pytest.raises(ValueError, match="Missing signer"):
        builder._validate_signature_requirements(init=True)


def test_create_signature_valid(builder):
    signer = Mock()
    signer.get_public_key.return_value = b"mock_public_key"
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(signer)

    signature = builder._create_signature()
    assert isinstance(signature, ED25519Signature)
    # Check the signer URL without "acc://"
    assert str(signature.signer) == "example.acme"
    assert signature.signer_version == builder.version
    assert signature.timestamp == builder.timestamp
    assert signature.public_key == b"mock_public_key"



def test_prepare_valid(builder):
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(Mock())
    signature = builder.prepare(init=True)
    assert isinstance(signature, ED25519Signature)
    assert str(signature.signer) == "example.acme"


def test_sign_valid(builder):
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(Mock())
    message = b"Test message"
    signature = builder.sign(message)
    assert signature.transaction_hash == hash_data(message)
    assert str(signature.signer) == "example.acme"

def test_initiate_valid(builder):
    builder.set_type(SignatureType.ED25519)
    builder.set_url(URL.parse("acc://example.acme"))
    builder.set_version(1)
    builder.set_timestamp(1234567890)
    builder.set_signer(Mock())
    txn = Mock()
    txn.get_hash.return_value = b"txn_hash"
    signature = builder.initiate(txn)
    assert signature.transaction_hash == txn.get_hash()
    assert str(signature.signer) == "example.acme"
