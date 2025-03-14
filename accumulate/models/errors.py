# accumulate-python-client\accumulate\models\errors.py

from enum import Enum
from typing import Optional


class ErrorCode(Enum):
    """
    Enumeration of error codes and their descriptions.
    """
    OK = (0, "Indicates the request succeeded")
    ENCODING_ERROR = (1, "Indicates something could not be decoded or encoded")
    FAILED = (2, "Indicates the request failed")
    DID_PANIC = (3, "Indicates the request failed due to a fatal error")
    UNKNOWN_ERROR = (4, "Indicates the request failed due to an unknown error")

    def __init__(self, value: int, description: str):
        self._value_ = value
        self.description = description

    def success(self) -> bool:
        """
        Determines if the error code represents a successful state.
        """
        return self == ErrorCode.OK

    @classmethod
    def from_value(cls, value: int) -> "ErrorCode":
        """
        Retrieve the error code enum from its integer value.

        :param value: The integer value of the error code.
        :return: The corresponding ErrorCode enum.
        :raises ValueError: If the value is not a valid error code.
        """
        for error in cls:
            if error.value == value:
                return error
        raise ValueError(f"Unknown ErrorCode value: {value}")

class AccumulateError(Exception):
    """
    Base class for Accumulate-related errors.
    """
    def __init__(self, code: ErrorCode, message: Optional[str] = None):
        self.code = code
        self.message = message or code.description
        super().__init__(f"[{self.code.name}] {self.message}")


# Specific Error Types
class EncodingError(AccumulateError):
    """
    Error raised when encoding or decoding fails.
    """
    def __init__(self, message: str = ErrorCode.ENCODING_ERROR.description):
        super().__init__(ErrorCode.ENCODING_ERROR, message)



class FailedError(AccumulateError):
    """
    Error raised for general failure cases.
    """
    def __init__(self, message: str = "Request failed"):
        super().__init__(ErrorCode.FAILED, message)


class PanicError(AccumulateError):
    """
    Error raised for fatal errors.
    """
    def __init__(self, message: str = "A fatal error occurred"):
        super().__init__(ErrorCode.DID_PANIC, message)


class UnknownError(AccumulateError):
    """
    Error raised for unknown issues.
    """
    def __init__(self, message: str = "An unknown error occurred"):
        super().__init__(ErrorCode.UNKNOWN_ERROR, message)


# Utility Functions
def raise_for_error_code(code: int, message: Optional[str] = None):
    """
    Raise the appropriate exception based on the error code.

    :param code: The error code as an integer.
    :param message: An optional message describing the error.
    :raises AccumulateError: The corresponding exception for the error code.
    """
    error_code = ErrorCode.from_value(code)
    if error_code == ErrorCode.OK:
        return  # No error

    error_map = {
        ErrorCode.ENCODING_ERROR: EncodingError,
        ErrorCode.FAILED: FailedError,
        ErrorCode.DID_PANIC: PanicError,
        ErrorCode.UNKNOWN_ERROR: UnknownError,
    }

    exception_class = error_map.get(error_code, AccumulateError)
    raise exception_class(message or error_code.description)


class ValidationError(Exception):
    """Raised when validation fails."""


# Example Usage
if __name__ == "__main__":
    try:
        raise_for_error_code(2, "Something went wrong!")
    except AccumulateError as e:
        print(e)
