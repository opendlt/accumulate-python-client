# accumulate-python-client\tests\test_models\test_errors.py

import pytest
from accumulate.models.errors import (
    ErrorCode,
    AccumulateError,
    EncodingError,
    FailedError,
    PanicError,
    UnknownError,
    raise_for_error_code,
)


def test_error_code_enum():
    """Test the ErrorCode enum values and descriptions."""
    assert ErrorCode.OK.value == 0
    assert ErrorCode.OK.description == "Indicates the request succeeded"

    assert ErrorCode.ENCODING_ERROR.value == 1
    assert ErrorCode.ENCODING_ERROR.description == "Indicates something could not be decoded or encoded"

    assert ErrorCode.FAILED.value == 2
    assert ErrorCode.FAILED.description == "Indicates the request failed"

    assert ErrorCode.DID_PANIC.value == 3
    assert ErrorCode.DID_PANIC.description == "Indicates the request failed due to a fatal error"

    assert ErrorCode.UNKNOWN_ERROR.value == 4
    assert ErrorCode.UNKNOWN_ERROR.description == "Indicates the request failed due to an unknown error"


def test_error_code_from_value():
    """Test retrieving ErrorCode from an integer value."""
    assert ErrorCode.from_value(0) == ErrorCode.OK
    assert ErrorCode.from_value(1) == ErrorCode.ENCODING_ERROR
    assert ErrorCode.from_value(2) == ErrorCode.FAILED
    assert ErrorCode.from_value(3) == ErrorCode.DID_PANIC
    assert ErrorCode.from_value(4) == ErrorCode.UNKNOWN_ERROR

    with pytest.raises(ValueError, match="Unknown ErrorCode value: 99"):
        ErrorCode.from_value(99)


def test_accumulate_error():
    """Test the base AccumulateError class."""
    error = AccumulateError(ErrorCode.FAILED, "Test message")
    assert error.code == ErrorCode.FAILED
    assert error.message == "Test message"
    assert str(error) == "[FAILED] Test message"


def test_encoding_error():
    """Test the EncodingError class."""
    error = EncodingError("Custom encoding error message")
    assert error.code == ErrorCode.ENCODING_ERROR
    assert error.message == "Custom encoding error message"
    assert str(error) == "[ENCODING_ERROR] Custom encoding error message"

    default_error = EncodingError()
    assert default_error.message == "Indicates something could not be decoded or encoded"
    assert str(default_error) == "[ENCODING_ERROR] Indicates something could not be decoded or encoded"


def test_failed_error():
    """Test the FailedError class."""
    error = FailedError("Custom failure message")
    assert error.code == ErrorCode.FAILED
    assert error.message == "Custom failure message"
    assert str(error) == "[FAILED] Custom failure message"

    default_error = FailedError()
    assert default_error.message == "Request failed"


def test_panic_error():
    """Test the PanicError class."""
    error = PanicError("Custom panic message")
    assert error.code == ErrorCode.DID_PANIC
    assert error.message == "Custom panic message"
    assert str(error) == "[DID_PANIC] Custom panic message"

    default_error = PanicError()
    assert default_error.message == "A fatal error occurred"


def test_unknown_error():
    """Test the UnknownError class."""
    error = UnknownError("Custom unknown error message")
    assert error.code == ErrorCode.UNKNOWN_ERROR
    assert error.message == "Custom unknown error message"
    assert str(error) == "[UNKNOWN_ERROR] Custom unknown error message"

    default_error = UnknownError()
    assert default_error.message == "An unknown error occurred"


def test_raise_for_error_code():
    """Test the raise_for_error_code utility function."""
    # No exception should be raised for OK
    assert raise_for_error_code(0) is None

    # Encoding error
    with pytest.raises(EncodingError, match="Indicates something could not be decoded or encoded"):
        raise_for_error_code(1)

    # Failed error
    with pytest.raises(FailedError, match="Indicates the request failed"):
        raise_for_error_code(2)

    # Panic error
    with pytest.raises(PanicError, match="Indicates the request failed due to a fatal error"):
        raise_for_error_code(3)

    # Unknown error
    with pytest.raises(UnknownError, match="Indicates the request failed due to an unknown error"):
        raise_for_error_code(4)

    # Custom message
    with pytest.raises(FailedError, match="Custom failure message"):
        raise_for_error_code(2, "Custom failure message")

    # Invalid error code
    with pytest.raises(ValueError, match="Unknown ErrorCode value: 99"):
        raise_for_error_code(99)

