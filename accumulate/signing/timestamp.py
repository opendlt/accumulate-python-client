# accumulate-python-client\accumulate\signing\timestamp.py

from abc import ABC, abstractmethod
import threading
import time

class Timestamp(ABC):
    """Abstract base class for timestamp implementations."""

    @abstractmethod
    def get(self) -> int:
        """
        Retrieve the current timestamp value.

        Returns:
            int: The current timestamp value.
        """
        pass

class TimestampFromValue(Timestamp):
    """Static timestamp that always returns a predefined value."""

    def __init__(self, value: int):
        if value < 0:
            raise ValueError("Timestamp value must be non-negative")
        self._value = value

    def get(self) -> int:
        """
        Retrieve the static timestamp value.

        Returns:
            int: The predefined timestamp value.
        """
        return self._value

class TimestampFromVariable(Timestamp):
    """Dynamic timestamp that starts with real time (in milliseconds) and increments."""

    def __init__(self, initial_value: int = None):
        if initial_value is None:
            initial_value = int(time.time() * 1e3)  # ⬅️ Now using milliseconds
        if initial_value < 0:
            raise ValueError("Initial timestamp value must be non-negative")
        self._value = initial_value
        self._lock = threading.Lock()

    def get(self) -> int:
        """Atomically increment and retrieve the timestamp value."""
        with self._lock:
            self._value += 1  # ⬅️ Increment by 1 millisecond
            return self._value

    def reset(self, value: int = 0):
        """
        Reset the timestamp to a specified value (primarily for testing).

        Args:
            value (int): The value to reset the timestamp to. Must be non-negative.

        Raises:
            ValueError: If the provided value is negative.
        """
        if value < 0:
            raise ValueError("Reset value must be non-negative")
        with self._lock:
            self._value = value

# Example Usage:
# static_ts = TimestampFromValue(1234567890)
# print(static_ts.get())  # Always returns 1234567890

# dynamic_ts = TimestampFromVariable()
# print(dynamic_ts.get())  # Returns current timestamp in milliseconds and increments
# dynamic_ts.reset(500)
# print(dynamic_ts.get())  # Resumes from 501
