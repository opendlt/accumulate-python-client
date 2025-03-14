# accumulate-python-client\accumulate\models\records.py

from dataclasses import dataclass, field
from typing import List, Optional, Type, TypeVar, Dict, Any, Generic
from datetime import datetime
from accumulate.models.options import RangeOptions

T = TypeVar("T", bound="Record")

class AccumulateError(Exception):
    """Base class for all custom exceptions in the Accumulate client."""
    pass

def range_of(record_range: "RecordRange", item_type: Type[T]) -> "RecordRange[T]":
    """Validate and cast a RecordRange to a specific item type."""
    if not all(isinstance(record, item_type) for record in record_range.records):
        raise AccumulateError(
            f"RecordRange contains items of an incorrect type. Expected {item_type}, "
            f"but got {[type(record) for record in record_range.records]}"
        )
    return record_range


@dataclass
class Record:
    """Base class for records in the Accumulate blockchain."""
    record_type: str = "UNKNOWN"
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": self.record_type,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Record":
        # Lazy import to resolve circular dependency
        RecordType = __import__("accumulate.models.enums").models.enums.RecordType
        return cls(
            record_type=data.get("record_type", "UNKNOWN"),
            data=data.get("data", {}),
        )


@dataclass
class UrlRecord(Record):
    """Represents a URL record."""
    value: Optional[str] = None

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "UrlRecord":
        return cls(value=data.get("value"))


@dataclass
class TxIDRecord(Record):
    """Represents a TxID record."""
    value: Optional[str] = None

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TxIDRecord":
        return cls(value=data.get("value"))


@dataclass
class RecordRange(Generic[T]):
    """Represents a range of records."""
    records: List[T] = field(default_factory=list)
    start: Optional[int] = None
    total: Optional[int] = None
    last_block_time: Optional[datetime] = None
    item_type: Type[T] = Record  # Add this field to define the type explicitly

    def to_dict(self) -> dict:
        return {
            "records": [record.to_dict() for record in self.records],
            "start": self.start,
            "total": self.total,
            "last_block_time": self.last_block_time.isoformat() if self.last_block_time else None,
        }

    @classmethod
    def from_dict(cls, data: Optional[dict], record_cls: Type[T]) -> "RecordRange[T]":
        if data is None:  # Handle None gracefully
            return cls(records=[], start=None, total=None, last_block_time=None, item_type=record_cls)
        return cls(
            records=[record_cls.from_dict(record) for record in data.get("records", [])],
            start=data.get("start"),
            total=data.get("total"),
            last_block_time=datetime.fromisoformat(data["last_block_time"]) if data.get("last_block_time") else None,
            item_type=record_cls
        )

@dataclass
class AccountRecord(Record):
    """Represents an account record."""
    account: Dict[str, Any] = field(default_factory=dict)
    directory: Optional[RecordRange[UrlRecord]] = field(default=None)
    pending: Optional[RecordRange[TxIDRecord]] = field(default=None)
    receipt: Optional[Dict[str, Any]] = field(default_factory=dict)
    last_block_time: Optional[datetime] = field(default=None)

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "directory": self.directory.to_dict() if self.directory else None,
            "pending": self.pending.to_dict() if self.pending else None,
            "receipt": self.receipt,
            "last_block_time": self.last_block_time.isoformat() if self.last_block_time else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AccountRecord":
        return cls(
            account=data["account"],
            directory=RecordRange.from_dict(data["directory"], UrlRecord) if data.get("directory") else None,
            pending=RecordRange.from_dict(data["records"], TxIDRecord) if data.get("records") else None,
            receipt=data.get("receipt", {}),
            last_block_time=datetime.fromisoformat(data["last_block_time"]) if data.get("last_block_time") else None,
        )

    @property
    def balance(self) -> float:
        """Convert raw balance (stored in micro-ACME) to actual ACME tokens."""
        raw_balance = int(self.account.get("balance", 0))  # Get the raw integer balance
        return raw_balance / 1e8  # Convert micro-ACME (1 ACME = 100,000,000 units)


@dataclass
class ChainRecord(Record):
    """Represents a chain record."""
    name: Optional[str] = None  # Optional to resolve field ordering
    type: Optional[str] = None  # Optional to resolve field ordering
    count: Optional[int] = None  # Optional to resolve field ordering
    state: List[bytes] = field(default_factory=list)  # Optional with a default factory
    last_block_time: Optional[datetime] = None  # Optional field

    def to_dict(self) -> dict:
        """Converts the ChainRecord to a dictionary."""
        return {
            "name": self.name,
            "type": self.type,
            "count": self.count,
            "state": self.state,
            "last_block_time": self.last_block_time.isoformat() if self.last_block_time else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChainRecord":
        """Creates a ChainRecord instance from a dictionary."""
        return cls(
            name=data.get("name"),
            type=data.get("type"),
            count=data.get("count"),
            state=data.get("state", []),  # Defaults to an empty list if not provided
            last_block_time=datetime.fromisoformat(data["last_block_time"]) if data.get("last_block_time") else None,
        )



@dataclass
class ChainEntryRecord(Record):
    """Represents a chain entry record."""
    name: Optional[str] = None
    type: Optional[str] = None
    count: Optional[int] = None
    state: List[bytes] = field(default_factory=list)
    account: Optional[str] = None
    index: Optional[int] = None
    entry: Optional[str] = None
    receipt: Optional[Dict[str, Any]] = field(default_factory=dict)
    last_block_time: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "count": self.count,
            "state": self.state,
            "account": self.account,
            "index": self.index,
            "entry": self.entry,
            "receipt": self.receipt,
            "last_block_time": self.last_block_time.isoformat() if self.last_block_time else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChainEntryRecord":
        return cls(
            name=data.get("name"),
            type=data.get("type"),
            count=data.get("count"),
            state=data.get("state", []),
            account=data.get("account"),
            index=data.get("index"),
            entry=data.get("entry"),
            receipt=data.get("receipt", {}),
            last_block_time=datetime.fromisoformat(data["last_block_time"]) if data.get("last_block_time") else None,
        )


@dataclass
class KeyRecord(Record):
    """Represents a key record."""
    authority: Optional[str] = None
    signer: Optional[str] = None
    version: Optional[int] = None
    index: Optional[int] = None
    entry: Optional[Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "authority": self.authority,
            "signer": self.signer,
            "version": self.version,
            "index": self.index,
            "entry": self.entry,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KeyRecord":
        return cls(
            authority=data.get("authority"),
            signer=data.get("signer"),
            version=data.get("version"),
            index=data.get("index"),
            entry=data.get("entry"),
        )


@dataclass
class MessageRecord(Record):
    """Represents a message record."""
    id: Optional[str] = None
    message: Optional[dict] = field(default_factory=dict)
    status: Optional[str] = None
    result: Optional[dict] = field(default_factory=dict)
    received: Optional[int] = None
    produced: Optional[RecordRange[TxIDRecord]] = field(default=None)
    cause: Optional[RecordRange[TxIDRecord]] = field(default=None)
    signatures: Optional[RecordRange["SignatureSetRecord"]] = field(default=None)
    historical: Optional[bool] = None
    last_block_time: Optional[datetime] = None

    def to_dict(self) -> dict:
        result = {
            "id": self.id,
            "message": self.message or {},
            "status": self.status,
            "result": self.result or {},
            "received": self.received,
            "produced": self.produced.to_dict() if self.produced else None,
            "cause": self.cause.to_dict() if self.cause else None,
            "signatures": self.signatures.to_dict() if self.signatures else None,
            "historical": self.historical,
            "last_block_time": self.last_block_time.isoformat() if self.last_block_time else None,
        }
        # Remove fields with None values
        return {key: value for key, value in result.items() if value is not None}

    @classmethod
    def from_dict(cls, data: dict) -> "MessageRecord":
        return cls(
            id=data.get("id"),
            message=data.get("message", {}),
            status=data.get("status"),
            result=data.get("result", {}),
            received=data.get("received"),
            produced=RecordRange.from_dict(data["produced"], TxIDRecord) if "produced" in data else None,
            cause=RecordRange.from_dict(data["cause"], TxIDRecord) if "cause" in data else None,
            signatures=RecordRange.from_dict(data["signatures"], SignatureSetRecord) if "signatures" in data else None,
            historical=data.get("historical"),
            last_block_time=datetime.fromisoformat(data["last_block_time"]) if data.get("last_block_time") else None,
        )


@dataclass
class SignatureSetRecord(Record):
    """Represents a signature set record."""
    account: Optional[dict] = field(default_factory=dict)
    signatures: Optional[RecordRange[MessageRecord]] = field(default=None)

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "signatures": self.signatures.to_dict() if self.signatures else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SignatureSetRecord":
        return cls(
            account=data.get("account", {}),
            signatures=RecordRange.from_dict(data["signatures"], MessageRecord) if "signatures" in data else None,
        )
