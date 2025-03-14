# accumulate-python-client\tests\test_api\test_context.py

import pytest
from accumulate.api.context import RequestContext

def test_request_context_initialization_without_metadata():
    """
    Test initializing RequestContext without passing metadata.
    """
    context = RequestContext()
    assert context.metadata == {}, "Metadata should be an empty dictionary by default."


def test_request_context_initialization_with_metadata():
    """
    Test initializing RequestContext with provided metadata.
    """
    metadata = {"key1": "value1", "key2": "value2"}
    context = RequestContext(metadata=metadata)
    assert context.metadata == metadata, "Metadata should match the provided dictionary."


def test_request_context_get_metadata_existing_key():
    """
    Test retrieving metadata for an existing key.
    """
    metadata = {"key1": "value1", "key2": "value2"}
    context = RequestContext(metadata=metadata)
    assert context.get_metadata("key1") == "value1", "Should return the value for the existing key"
    assert context.get_metadata("key2") == "value2", "Should return the value for the existing key"


def test_request_context_get_metadata_nonexistent_key():
    """
    Test retrieving metadata for a key that does not exist.
    """
    context = RequestContext(metadata={"key1": "value1"})
    assert context.get_metadata("key2") is None, "Should return None for a nonexistent key"


def test_request_context_set_metadata_new_key():
    """
    Test setting metadata for a new key.
    """
    context = RequestContext()
    context.set_metadata("key1", "value1")
    assert context.metadata == {"key1": "value1"}, "Metadata should contain the new key-value pair."


def test_request_context_set_metadata_existing_key():
    """
    Test updating metadata for an existing key.
    """
    context = RequestContext(metadata={"key1": "value1"})
    context.set_metadata("key1", "new_value")
    assert context.metadata == {"key1": "new_value"}, "Metadata should update the value for the existing key."


def test_request_context_set_multiple_metadata():
    """
    Test setting multiple metadata values sequentially.
    """
    context = RequestContext()
    context.set_metadata("key1", "value1")
    context.set_metadata("key2", "value2")
    assert context.metadata == {"key1": "value1", "key2": "value2"}, "Metadata should include all set key-value pairs."


def test_request_context_get_metadata_with_empty_context():
    """
    Test retrieving metadata from an empty RequestContext.
    """
    context = RequestContext()
    assert context.get_metadata("any_key") is None, "Should return None when metadata is empty."
