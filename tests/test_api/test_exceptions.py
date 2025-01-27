# accumulate-python-client\tests\test_api\test_exceptions.py

import pytest
from accumulate.api.exceptions import (
    AccumulateError,
    QueryError,
    SubmissionError,
    ValidationError,
    FaucetError,
)


def test_accumulate_error_initialization():
    """
    Test the initialization and message assignment of AccumulateError.
    """
    error = AccumulateError("This is a base error.")
    assert str(error) == "This is a base error.", "Error message should match the initialization string."


def test_query_error_initialization():
    """
    Test the initialization and message assignment of QueryError.
    """
    error = QueryError("This is a query error.")
    assert isinstance(error, AccumulateError), "QueryError should be a subclass of AccumulateError."
    assert str(error) == "This is a query error.", "Error message should match the initialization string."


def test_submission_error_initialization():
    """
    Test the initialization and message assignment of SubmissionError.
    """
    error = SubmissionError("This is a submission error.")
    assert isinstance(error, AccumulateError), "SubmissionError should be a subclass of AccumulateError."
    assert str(error) == "This is a submission error.", "Error message should match the initialization string."


def test_validation_error_initialization():
    """
    Test the initialization and message assignment of ValidationError.
    """
    error = ValidationError("This is a validation error.")
    assert isinstance(error, AccumulateError), "ValidationError should be a subclass of AccumulateError."
    assert str(error) == "This is a validation error.", "Error message should match the initialization string."


def test_faucet_error_initialization():
    """
    Test the initialization and message assignment of FaucetError.
    """
    error = FaucetError("This is a faucet error.")
    assert isinstance(error, AccumulateError), "FaucetError should be a subclass of AccumulateError."
    assert str(error) == "This is a faucet error.", "Error message should match the initialization string."


def test_error_raising_and_handling():
    """
    Test raising and catching all custom exceptions.
    """
    with pytest.raises(AccumulateError, match="Base error raised"):
        raise AccumulateError("Base error raised")

    with pytest.raises(QueryError, match="Query error raised"):
        raise QueryError("Query error raised")

    with pytest.raises(SubmissionError, match="Submission error raised"):
        raise SubmissionError("Submission error raised")

    with pytest.raises(ValidationError, match="Validation error raised"):
        raise ValidationError("Validation error raised")

    with pytest.raises(FaucetError, match="Faucet error raised"):
        raise FaucetError("Faucet error raised")
