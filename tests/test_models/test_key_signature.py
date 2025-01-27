# accumulate-python-client\tests\test_models\test_key_signature.py

import pytest
import hashlib
from accumulate.models.key_signature import KeySignature, BasicKeySignature


def test_key_signature_abstract_methods():
    """
    Ensure KeySignature's abstract methods raise NotImplementedError.
    """
    class DummyKeySignature(KeySignature):
        def get_signature(self):
            raise NotImplementedError()

        def get_public_key_hash(self):
            raise NotImplementedError()

        def get_public_key(self):
            raise NotImplementedError()

        def get_signer_version(self):
            raise NotImplementedError()

        def get_timestamp(self):
            raise NotImplementedError()

    # Instantiate the DummyKeySignature class
    dummy = DummyKeySignature()

    # Check that each method raises NotImplementedError
    with pytest.raises(NotImplementedError):
        dummy.get_signature()

    with pytest.raises(NotImplementedError):
        dummy.get_public_key_hash()

    with pytest.raises(NotImplementedError):
        dummy.get_public_key()

    with pytest.raises(NotImplementedError):
        dummy.get_signer_version()

    with pytest.raises(NotImplementedError):
        dummy.get_timestamp()

@pytest.fixture
def basic_key_signature():
    """
    Fixture for creating a BasicKeySignature object with sample data.
    """
    return BasicKeySignature(
        signature=b"sample_signature",
        public_key=b"sample_public_key",
        signer_version=1,
        timestamp=1234567890,
    )


def test_basic_key_signature_initialization(basic_key_signature):
    """
    Test the initialization of BasicKeySignature.
    """
    assert basic_key_signature.get_signature() == b"sample_signature"
    assert basic_key_signature.get_public_key() == b"sample_public_key"
    assert basic_key_signature.get_signer_version() == 1
    assert basic_key_signature.get_timestamp() == 1234567890


def test_basic_key_signature_public_key_hash(basic_key_signature):
    """
    Test the public key hash generation.
    """
    expected_hash = hashlib.sha256(b"sample_public_key").digest()
    assert basic_key_signature.get_public_key_hash() == expected_hash


def test_basic_key_signature_signature(basic_key_signature):
    """
    Test the retrieval of the signature.
    """
    assert basic_key_signature.get_signature() == b"sample_signature"


def test_basic_key_signature_public_key(basic_key_signature):
    """
    Test the retrieval of the public key.
    """
    assert basic_key_signature.get_public_key() == b"sample_public_key"


def test_basic_key_signature_signer_version(basic_key_signature):
    """
    Test the retrieval of the signer version.
    """
    assert basic_key_signature.get_signer_version() == 1


def test_basic_key_signature_timestamp(basic_key_signature):
    """
    Test the retrieval of the timestamp.
    """
    assert basic_key_signature.get_timestamp() == 1234567890


def test_basic_key_signature_edge_cases():
    """
    Test edge cases for BasicKeySignature.
    """
    # Empty values
    empty_signature = BasicKeySignature(
        signature=b"",
        public_key=b"",
        signer_version=0,
        timestamp=0,
    )
    assert empty_signature.get_signature() == b""
    assert empty_signature.get_public_key() == b""
    assert empty_signature.get_signer_version() == 0
    assert empty_signature.get_timestamp() == 0
    assert empty_signature.get_public_key_hash() == hashlib.sha256(b"").digest()

    # Large input values
    large_signature = b"a" * 10**6
    large_public_key = b"b" * 10**6
    large_key_signature = BasicKeySignature(
        signature=large_signature,
        public_key=large_public_key,
        signer_version=10**6,
        timestamp=2**31 - 1,
    )
    assert large_key_signature.get_signature() == large_signature
    assert large_key_signature.get_public_key() == large_public_key
    assert large_key_signature.get_signer_version() == 10**6
    assert large_key_signature.get_timestamp() == 2**31 - 1
    assert large_key_signature.get_public_key_hash() == hashlib.sha256(large_public_key).digest()
