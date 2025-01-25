# C:\Accumulate_Stuff\accumulate-python-client\accumulate\api\exceptions.py

class AccumulateError(Exception):
    """Base class for all custom exceptions in the Accumulate client."""
    pass


class QueryError(AccumulateError):
    """Raised when a query to the RPC API fails."""
    pass


class SubmissionError(AccumulateError):
    """Raised when a transaction submission fails."""
    pass


class ValidationError(AccumulateError):
    """Raised when validation fails."""
    pass


class FaucetError(AccumulateError):
    """Raised when faucet token requests fail."""
    pass
