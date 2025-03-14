# accumulate-python-client\accumulate\utils\union.py

import json
from typing import  Union, Any


class UnionValue:
    """
    A Pythonic implementation for managing values with multiple representations,
    inspired by Go's UnionValue interface
    """

    def __init__(self, value: Union[bytes, str, int, float, None] = None):
        self.value = value

    def marshal_binary(self) -> bytes:
        """Convert the value to its binary representation"""
        if isinstance(self.value, bytes):
            return self.value
        elif isinstance(self.value, str):
            return self.value.encode("utf-8")
        elif isinstance(self.value, (int, float)):
            return str(self.value).encode("utf-8")
        else:
            raise ValueError("Cannot marshal value to binary")

    def unmarshal_binary(self, data: bytes):
        """Set the value from its binary representation"""
        self.value = data

    def marshal_json(self) -> str:
        """Convert the value to its JSON representation"""
        try:
            return json.dumps(self.value)
        except TypeError:
            raise ValueError("Value cannot be converted to JSON")

    def unmarshal_json(self, data: str):
        """Set the value from its JSON representation"""
        try:
            self.value = json.loads(data)
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON representation")

    def copy(self) -> "UnionValue":
        """Create a copy of the current UnionValue"""
        return UnionValue(self.value)

    def __eq__(self, other: Any) -> bool:
        """Check equality between two UnionValue instances"""
        if not isinstance(other, UnionValue):
            return False
        return self.value == other.value

    def __hash__(self):
        """Allow the UnionValue to be used in hashable collections"""
        return hash(self.value)

    def __repr__(self):
        """Human-readable representation"""
        return f"UnionValue(value={repr(self.value)})"