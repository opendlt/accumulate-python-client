# accumulate-python-client\accumulate\models\base_transactions.py

from abc import ABC, abstractmethod
from typing import Any, Optional
from accumulate.models.enums import TransactionType


class TransactionBody(ABC):
    """
    Abstract base class for transaction bodies.
    Defines the structure and required methods for all transaction body types.
    """

    @abstractmethod
    def type(self) -> TransactionType:
        """Return the type of the transaction."""
        pass

    @abstractmethod
    def marshal(self) -> bytes:
        """Serialize the transaction body to bytes."""
        pass

    @abstractmethod
    def unmarshal(self, data: bytes) -> Any:
        """Deserialize the transaction body from bytes."""
        pass


class TransactionHeader:
    """
    Represents the header of a transaction, containing metadata and conditions.
    """

    def __init__(
        self,
        principal: str,  # URL or identifier of the principal account
        initiator: Optional[bytes] = None,
        memo: Optional[str] = None,
        metadata: Optional[bytes] = None,
        expire: Optional["ExpireOptions"] = None,
        hold_until: Optional["HoldUntilOptions"] = None,
        authorities: Optional[list] = None,
    ):
        """
        :param principal: The principal account associated with the transaction.
        :param initiator: Hash of the initiator of the transaction.
        :param memo: Optional memo string for the transaction.
        :param metadata: Optional metadata in bytes.
        :param expire: Expiration conditions for the transaction.
        :param hold_until: Hold conditions for the transaction.
        :param authorities: List of additional authorities required for approval.
        """
        self.principal = principal
        self.initiator = initiator
        self.memo = memo
        self.metadata = metadata
        self.expire = expire
        self.hold_until = hold_until
        self.authorities = authorities or []

    def marshal_binary(self) -> bytes:
        """Serialize the transaction header to bytes."""
        # Implementation omitted for brevity
        pass

    @staticmethod
    def unmarshal(data: bytes) -> "TransactionHeader":
        """Deserialize the transaction header from bytes."""
        # Implementation omitted for brevity
        pass


class ExpireOptions:
    """
    Represents expiration options for a transaction.
    """

    def __init__(self, at_time: Optional[int] = None):
        """
        :param at_time: The expiration time as a Unix timestamp.
        """
        self.at_time = at_time


class HoldUntilOptions:
    """
    Represents hold-until options for a transaction.
    """

    def __init__(self, minor_block: Optional[int] = None):
        """
        :param minor_block: The minor block at which the transaction is held until.
        """
        self.minor_block = minor_block
