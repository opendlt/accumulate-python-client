# accumulate-python-client\accumulate\utils\fields.py

from datetime import datetime, timedelta
from typing import Any, Optional, Type, Callable

class Field:
    """Base class for field access and validation"""

    def __init__(self, name: str, required: bool = False, omit_empty: bool = False):
        self.name = name
        self.required = required
        self.omit_empty = omit_empty

    def is_empty(self, value: Any) -> bool:
        """Check if a field value is empty"""
        return value is None or (isinstance(value, (str, list, dict)) and len(value) == 0)

    def to_json(self, value: Any) -> Optional[Any]:
        """Serialize the field to JSON"""
        if self.omit_empty and self.is_empty(value):
            return None
        return value

    def from_json(self, data: dict, instance: Any) -> None:
        """Deserialize the field from JSON"""
        if self.name in data:
            setattr(instance, self.name, data[self.name])


class IntField(Field):
    """Field for integer values"""

    def to_json(self, value: int) -> Optional[int]:
        if self.omit_empty and value == 0:
            return None
        return value


class StringField(Field):
    """Field for string values"""

    def to_json(self, value: str) -> Optional[str]:
        if self.omit_empty and not value:
            return None
        return value


class BoolField(Field):
    """Field for boolean values"""

    def to_json(self, value: bool) -> Optional[bool]:
        if self.omit_empty and value is False:
            return None
        return value


class DateTimeField(Field):
    """Field for datetime values"""

    def to_json(self, value: datetime) -> Optional[str]:
        if self.omit_empty and value is None:
            return None
        return value.isoformat() if isinstance(value, datetime) else None

    def from_json(self, data: dict, instance: Any) -> None:
        if self.name in data:
            try:
                setattr(instance, self.name, datetime.fromisoformat(data[self.name]))
            except ValueError:
                raise ValueError(f"Invalid datetime format for field {self.name}: {data[self.name]}")


class FloatField(Field):
    """Field for float values"""

    def to_json(self, value: float) -> Optional[float]:
        if self.omit_empty and value == 0.0:
            return None
        return value


class ReadOnlyAccessor:
    """Read-only accessor for managing field serialization and equality checks"""

    def __init__(self, accessor: Callable[[Any], Any]):
        """
        Initialize with a callable that provides access to the field value
        :param accessor: A callable that takes a parent object and returns the field value
        """
        self._accessor = accessor

    def is_empty(self, obj: Any) -> bool:
        """Check if the field is empty"""
        value = self._accessor(obj)
        return value is None or value == "" or value == 0

    def equal(self, obj1: Any, obj2: Any) -> bool:
        """Check if two objects have equal field values"""
        return self._accessor(obj1) == self._accessor(obj2)

    def to_json(self, obj: Any) -> Any:
        """Convert the field value to a JSON-compatible format"""
        value = self._accessor(obj)
        if isinstance(value, (int, float, str, dict, list)):
            return value
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if hasattr(value, "__dict__"):
            return value.__dict__
        raise ValueError(f"Cannot serialize value of type {type(value).__name__}")

    def write_to(self, obj: Any) -> bytes:
        """
        Serialize the field value into binary
        For demonstration, this simply converts the value to bytes if possible
        """
        value = self._accessor(obj)
        if isinstance(value, (int, float)):
            return str(value).encode()
        if isinstance(value, str):
            return value.encode()
        if isinstance(value, bytes):
            return value
        raise ValueError(f"Cannot write value of type {type(value).__name__} to binary")

    # Prevent modifications
    def copy_to(self, dst: Any, src: Any):
        """Read-only accessor does not support copying"""
        raise NotImplementedError("ReadOnlyAccessor does not support copying values")

    def read_from(self, data: bytes, obj: Any):
        """Read-only accessor does not support deserialization"""
        raise NotImplementedError("ReadOnlyAccessor does not support deserialization")

    def from_json(self, json_data: Any, obj: Any):
        """Read-only accessor does not support deserialization from JSON"""
        raise NotImplementedError("ReadOnlyAccessor does not support deserialization from JSON")


class DurationField(Field):
    """Field for timedelta (duration) values."""

    def to_json(self, value: timedelta) -> Optional[dict]:
        """Convert a timedelta to a JSON-compatible dictionary"""
        if self.omit_empty and value == timedelta(0):
            return None
        seconds = value.seconds + value.days * 86400  # Total seconds including days
        nanoseconds = value.microseconds * 1000  # Convert microseconds to nanoseconds
        return {"seconds": seconds, "nanoseconds": nanoseconds}

    def from_json(self, data: dict, instance: Any) -> None:
        """Convert a JSON-compatible dictionary back to a timedelta"""
        if self.name in data:
            fields = data[self.name]
            seconds = fields.get("seconds", 0)
            nanoseconds = fields.get("nanoseconds", 0)
            setattr(
                instance,
                self.name,
                timedelta(seconds=seconds, microseconds=nanoseconds / 1000),
            )

    def is_empty(self, value: timedelta) -> bool:
        """Check if the timedelta is empty (default value)"""
        return value == timedelta(0)


class TimeAccessor(ReadOnlyAccessor):
    """Accessor for managing datetime fields"""

    def __init__(self, accessor: Callable[[Any], datetime]):
        super().__init__(accessor)

    def to_json(self, obj: Any) -> Optional[str]:
        """Convert a datetime field to JSON-compatible ISO format"""
        value = self._accessor(obj)
        return None if value is None else value.isoformat()
