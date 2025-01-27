# accumulate-python-client\accumulate\models\transaction_results.py

from typing import Optional, Union, Dict, Any
from accumulate.utils.url import URL


class TransactionResult:
    """
    Base class for transaction results.
    """
    def copy(self) -> "TransactionResult":
        raise NotImplementedError("Subclasses must implement this method.")

    def equal(self, other: "TransactionResult") -> bool:
        raise NotImplementedError("Subclasses must implement this method.")


class EmptyResult(TransactionResult):
    """
    Represents an empty transaction result.
    """
    def copy(self) -> "EmptyResult":
        return EmptyResult()

    def equal(self, other: "EmptyResult") -> bool:
        return isinstance(other, EmptyResult)


class WriteDataResult(TransactionResult):
    """
    Represents the result of a Write Data transaction.

    :param entry_hash: The hash of the data entry.
    :param account_url: The URL of the account associated with the entry.
    :param account_id: The ID of the account associated with the entry.
    """
    def __init__(
        self,
        entry_hash: bytes = b"",
        account_url: Optional[URL] = None,
        account_id: Optional[bytes] = None,
    ):
        self.entry_hash = entry_hash
        self.account_url = account_url
        self.account_id = account_id

    def copy(self) -> "WriteDataResult":
        return WriteDataResult(self.entry_hash, self.account_url, self.account_id)

    def equal(self, other: "WriteDataResult") -> bool:
        return (
            isinstance(other, WriteDataResult) and
            self.entry_hash == other.entry_hash and
            self.account_url == other.account_url and
            self.account_id == other.account_id
        )


class AddCreditsResult(TransactionResult):
    """
    Represents the result of an Add Credits transaction.

    :param amount: The amount of tokens added.
    :param credits: The number of credits added.
    :param oracle: The oracle rate used for conversion.
    """
    def __init__(self, amount: int = 0, credits: int = 0, oracle: int = 0):
        if amount < 0 or credits < 0 or oracle < 0:
            raise ValueError("Amount, credits, and oracle must be non-negative integers.")
        self.amount = amount
        self.credits = credits
        self.oracle = oracle

    def copy(self) -> "AddCreditsResult":
        return AddCreditsResult(self.amount, self.credits, self.oracle)

    def equal(self, other: "AddCreditsResult") -> bool:
        return (
            isinstance(other, AddCreditsResult) and
            self.amount == other.amount and
            self.credits == other.credits and
            self.oracle == other.oracle
        )


def new_transaction_result(typ: str) -> TransactionResult:
    """
    Factory method to create a new transaction result based on the type.

    :param typ: The transaction type.
    :return: A new instance of the appropriate TransactionResult subclass.
    """
    if typ == "WriteDataResult":
        return WriteDataResult()
    elif typ == "AddCreditsResult":
        return AddCreditsResult()
    elif typ == "EmptyResult":
        return EmptyResult()
    raise ValueError(f"Unknown transaction result type: {typ}")


def equal_transaction_result(a: TransactionResult, b: TransactionResult) -> bool:
    """
    Compare two transaction results for equality.

    :param a: The first transaction result.
    :param b: The second transaction result.
    :return: True if they are equal, False otherwise.
    """
    return a.equal(b)


def unmarshal_transaction_result(data: Union[bytes, Dict[str, Any]]) -> TransactionResult:
    """
    Deserialize a transaction result from raw data or JSON.

    :param data: Raw bytes or JSON object containing the transaction result.
    :return: The deserialized TransactionResult.
    """
    if isinstance(data, bytes):
        data = deserialize_json(data)

    result_type = data.get("Type")
    if not result_type:
        raise ValueError("Missing transaction result type in data")

    result = new_transaction_result(result_type)

    # Deserialize fields and handle bytes explicitly
    for key, value in data.items():
        if key.lower() == "entry_hash" or key.lower() == "account_id":
            # Convert hex strings back to bytes
            setattr(result, key.lower(), bytes.fromhex(value) if isinstance(value, str) else value)
        elif key.lower() == "account_url" and isinstance(value, str):
            # Convert string to URL object
            setattr(result, key.lower(), URL.parse(value))
        else:
            setattr(result, key.lower(), value)

    return result



def copy_transaction_result(result: TransactionResult) -> TransactionResult:
    """
    Create a copy of the transaction result.

    :param result: The transaction result to copy.
    :return: A copy of the transaction result.
    """
    return result.copy()


def deserialize_json(data: bytes) -> Dict[str, Any]:
    """
    Deserialize JSON bytes into a dictionary.

    :param data: JSON bytes.
    :return: A dictionary representation of the JSON data.
    """
    import json
    return json.loads(data)
