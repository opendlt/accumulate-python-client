# accumulate-python-client\accumulate\utils\protocols.py

from typing import Protocol, runtime_checkable, Any, BinaryIO

@runtime_checkable
class BinaryValue(Protocol):
    """Protocol for objects supporting binary serialization and deserialization."""
    def marshal_binary(self) -> bytes:
        """Serialize to binary format."""
        raise NotImplementedError("marshal_binary must be implemented")

    def unmarshal_binary(self, data: bytes) -> None:
        """Deserialize from binary format."""
        raise NotImplementedError("unmarshal_binary must be implemented")

    def copy_as_interface(self) -> Any:
        """Create a copy of the instance."""
        raise NotImplementedError("copy_as_interface must be implemented")

    def unmarshal_binary_from(self, reader: BinaryIO) -> None:
        """Unmarshal binary data from a stream."""
        raise NotImplementedError("unmarshal_binary_from must be implemented")

@runtime_checkable
class UnionValue(BinaryValue, Protocol):
    """Protocol for objects supporting field unmarshaling."""
    def unmarshal_fields_from(self, reader: BinaryIO) -> None:
        """Unmarshal fields from a binary stream."""
        raise NotImplementedError("unmarshal_fields_from must be implemented")
