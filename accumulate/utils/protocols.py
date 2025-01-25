# C:\Accumulate_Stuff\accumulate-python-client\accumulate\utils\protocols.py

from typing import Protocol, runtime_checkable, Any, BinaryIO


@runtime_checkable
class BinaryValue(Protocol):
    """Protocol for objects supporting binary serialization and deserialization."""
    def marshal_binary(self) -> bytes:
        """Serialize to binary format."""
        ...

    def unmarshal_binary(self, data: bytes) -> None:
        """Deserialize from binary format."""
        ...

    def copy_as_interface(self) -> Any:
        """Create a copy of the instance."""
        ...

    def unmarshal_binary_from(self, reader: BinaryIO) -> None:
        """Unmarshal binary data from a stream."""
        ...


@runtime_checkable
class UnionValue(BinaryValue, Protocol):
    """Protocol for objects supporting field unmarshaling."""
    def unmarshal_fields_from(self, reader: BinaryIO) -> None:
        """Unmarshal fields from a binary stream."""
        ...
