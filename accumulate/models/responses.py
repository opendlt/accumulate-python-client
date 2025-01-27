# accumulate-python-client\accumulate\models\responses.py

from dataclasses import dataclass
from typing import List, Optional
from accumulate.models.protocol import Receipt
from accumulate.models.transactions import TransactionStatus

@dataclass
class SubmissionResponse:
    """Represents the response for a transaction submission."""
    status: Optional[TransactionStatus] = None
    success: bool = False
    message: Optional[str] = None
    receipt: Optional[Receipt] = None  # Added Receipt integration

    def to_dict(self) -> dict:
        """Serialize the response to a dictionary."""
        serialized_data = {
            "status": self.status.to_dict() if self.status else None,
            "success": self.success,
            "message": self.message,
            "receipt": self.receipt.to_dict() if self.receipt else None,  # Serialize Receipt
        }
        print(f"[DEBUG] Serialized SubmissionResponse: {serialized_data}")
        return serialized_data

    @classmethod
    def from_dict(cls, data: dict) -> "SubmissionResponse":
        """Deserialize the response from a dictionary."""
        print(f"[DEBUG] Deserializing SubmissionResponse from data: {data}")
        status = TransactionStatus.from_dict(data["status"]) if data.get("status") else None
        print(f"[DEBUG] Deserialized status: {status.to_dict() if status else None}")
        receipt = Receipt.from_dict(data["receipt"]) if data.get("receipt") else None
        print(f"[DEBUG] Deserialized receipt: {receipt.to_dict() if receipt else None}")
        response = cls(
            status=status,
            success=data.get("success", False),
            message=data.get("message"),
            receipt=receipt,
        )
        print(f"[DEBUG] Final SubmissionResponse object: {response}")
        return response


@dataclass
class TransactionResultSet:
    """Represents a set of transaction results returned from a query."""
    results: List[TransactionStatus] = None

    def __post_init__(self):
        if self.results is None:
            self.results = []

    def add_result(self, result: TransactionStatus):
        """Add a transaction status to the results."""
        print(f"[DEBUG] Adding result: {result.to_dict()}")
        self.results.append(result)

    def to_dict(self) -> dict:
        """Convert the result set to a dictionary representation."""
        serialized_data = {"results": [result.to_dict() for result in self.results]}
        print(f"[DEBUG] Serialized TransactionResultSet: {serialized_data}")
        return serialized_data

    @classmethod
    def from_dict(cls, data: dict) -> "TransactionResultSet":
        """Create a TransactionResultSet from a dictionary."""
        print(f"[DEBUG] Deserializing TransactionResultSet from data: {data}")
        results = [
            TransactionStatus.from_dict(item) for item in data.get("results", [])
        ]
        for i, result in enumerate(results):
            print(f"[DEBUG] Deserialized result {i}: {result.to_dict()}")
        result_set = cls(results)
        print(f"[DEBUG] Final TransactionResultSet object: {result_set}")
        return result_set
