# accumulate-python-client\accumulate\models\submission.py

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class Submission:
    """
    Represents a transaction submission in the Accumulate blockchain.
    """
    txid: Optional[str] = None  # Add `txid` field
    status: Optional[Dict[str, Any]] = None  # Corresponds to protocol.TransactionStatus
    success: bool = False  # Indicates whether the envelope was successfully submitted
    message: Optional[str] = None  # Message returned by the consensus engine

    def __post_init__(self):
        if self.status is not None and not isinstance(self.status, dict):
            raise TypeError("The 'status' field must be a dictionary or None.")

    def to_dict(self) -> dict:
        """
        Converts the Submission instance to a dictionary.
        """
        return {
            "txid": self.txid,
            "status": self.status,
            "success": self.success,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Submission":
        """
        Creates a Submission instance from a dictionary.
        """
        return cls(
            txid=data.get("txid"),  # extract the `txid` field
            status=data.get("status"),
            success=data.get("success", False),
            message=data.get("message"),
        )
