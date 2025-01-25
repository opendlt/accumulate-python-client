# C:\Accumulate_Stuff\accumulate-python-client\tests\test_utils\test_protocols.py


import pytest
from typing import Any, BinaryIO
from accumulate.utils.protocols import BinaryValue, UnionValue

# --- Test Fixtures ---
class MockBinaryValue:
    """Mock implementation of the BinaryValue protocol."""
    def __init__(self):
        self.data = b""

    def marshal_binary(self) -> bytes:
        return self.data

    def unmarshal_binary(self, data: bytes) -> None:
        self.data = data

    def copy_as_interface(self) -> Any:
        return MockBinaryValue()

    def unmarshal_binary_from(self, reader: BinaryIO) -> None:
        self.data = reader.read()

class MockUnionValue(MockBinaryValue, UnionValue):
    """Mock implementation of the UnionValue protocol."""
    def unmarshal_fields_from(self, reader: BinaryIO) -> None:
        self.data = reader.read()


# --- Tests for BinaryValue Protocol ---
def test_binary_value_protocol_compliance():
    """Test compliance with BinaryValue protocol."""
    mock_obj = MockBinaryValue()
    assert isinstance(mock_obj, BinaryValue)


def test_binary_value_marshal_binary():
    """Test marshalling to binary format."""
    mock_obj = MockBinaryValue()
    mock_obj.data = b"test_data"
    assert mock_obj.marshal_binary() == b"test_data"


def test_binary_value_unmarshal_binary():
    """Test unmarshalling from binary data."""
    mock_obj = MockBinaryValue()
    mock_obj.unmarshal_binary(b"new_data")
    assert mock_obj.data == b"new_data"


def test_binary_value_copy_as_interface():
    """Test copying as an interface."""
    mock_obj = MockBinaryValue()
    copy_obj = mock_obj.copy_as_interface()
    assert isinstance(copy_obj, MockBinaryValue)
    assert copy_obj is not mock_obj


def test_binary_value_unmarshal_binary_from():
    """Test unmarshalling binary data from a stream."""
    import io
    mock_obj = MockBinaryValue()
    stream = io.BytesIO(b"stream_data")
    mock_obj.unmarshal_binary_from(stream)
    assert mock_obj.data == b"stream_data"


# --- Tests for UnionValue Protocol ---
def test_union_value_protocol_compliance():
    """Test compliance with UnionValue protocol."""
    mock_obj = MockUnionValue()
    assert isinstance(mock_obj, UnionValue)


def test_union_value_unmarshal_fields_from():
    """Test unmarshalling fields from a binary stream."""
    import io
    mock_obj = MockUnionValue()
    stream = io.BytesIO(b"field_data")
    mock_obj.unmarshal_fields_from(stream)
    assert mock_obj.data == b"field_data"
