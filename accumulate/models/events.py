# accumulate-python-client\accumulate\models\events.py

from typing import List, Optional, Dict, Any
from datetime import datetime
from accumulate.models.records import Record


class ErrorEvent:
    """Represents an error event in the system."""

    def __init__(self, err: Optional[Dict[str, Any]] = None):
        self.err = err

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {"err": self.err}

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ErrorEvent":
        """Create an ErrorEvent from a dictionary."""
        return ErrorEvent(err=data.get("err"))


class BlockEvent(Record):
    """Represents a block event."""

    def __init__(
        self,
        partition: str,
        index: int,
        time: datetime,
        major: int,
        entries: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(record_type="BlockEvent")
        self.partition = partition
        self.index = index
        self.time = time
        self.major = major
        self.entries = entries or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "record_type": self.record_type,
            "partition": self.partition,
            "index": self.index,
            "time": self.time.isoformat(),
            "major": self.major,
            "entries": self.entries,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "BlockEvent":
        """Create a BlockEvent from a dictionary."""
        return BlockEvent(
            partition=data["partition"],
            index=data["index"],
            time=datetime.fromisoformat(data["time"]),
            major=data["major"],
            entries=data.get("entries", []),
        )



class GlobalsEvent:
    """Represents a global values change event."""

    def __init__(self, old: Optional[Dict[str, Any]] = None, new: Optional[Dict[str, Any]] = None):
        self.old = old
        self.new = new

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {"old": self.old, "new": self.new}

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "GlobalsEvent":
        """Create a GlobalsEvent from a dictionary."""
        return GlobalsEvent(
            old=data.get("old"),
            new=data.get("new"),
        )
