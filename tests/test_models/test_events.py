# accumulate-python-client\tests\test_models\test_events.py

import pytest
from datetime import datetime, timezone
from accumulate.models.events import ErrorEvent, BlockEvent, GlobalsEvent


def test_error_event_to_dict():
    """Test the to_dict method of ErrorEvent."""
    event = ErrorEvent(err={"code": 1, "message": "An error occurred"})
    expected_dict = {"err": {"code": 1, "message": "An error occurred"}}
    assert event.to_dict() == expected_dict


def test_error_event_from_dict():
    """Test the from_dict method of ErrorEvent."""
    data = {"err": {"code": 1, "message": "An error occurred"}}
    event = ErrorEvent.from_dict(data)
    assert event.err == data["err"]

    # Test with no error provided
    event_no_error = ErrorEvent.from_dict({})
    assert event_no_error.err is None


def test_block_event_to_dict():
    """Test the to_dict method of BlockEvent."""
    time = datetime.now(timezone.utc)
    event = BlockEvent(
        partition="partition1",
        index=42,
        time=time,
        major=1,
        entries=[{"key": "value"}],
    )
    expected_dict = {
        "record_type": "BlockEvent",
        "partition": "partition1",
        "index": 42,
        "time": time.isoformat(),
        "major": 1,
        "entries": [{"key": "value"}],
    }
    assert event.to_dict() == expected_dict


def test_block_event_from_dict():
    """Test the from_dict method of BlockEvent."""
    time = datetime.now(timezone.utc).isoformat()
    data = {
        "partition": "partition1",
        "index": 42,
        "time": time,
        "major": 1,
        "entries": [{"key": "value"}],
    }
    event = BlockEvent.from_dict(data)
    assert event.partition == "partition1"
    assert event.index == 42
    assert event.time.isoformat() == time
    assert event.major == 1
    assert event.entries == [{"key": "value"}]

    # Test with no entries
    data_no_entries = {
        "partition": "partition1",
        "index": 42,
        "time": time,
        "major": 1,
    }
    event_no_entries = BlockEvent.from_dict(data_no_entries)
    assert event_no_entries.entries == []


def test_globals_event_to_dict():
    """Test the to_dict method of GlobalsEvent."""
    event = GlobalsEvent(
        old={"key": "old_value"},
        new={"key": "new_value"},
    )
    expected_dict = {"old": {"key": "old_value"}, "new": {"key": "new_value"}}
    assert event.to_dict() == expected_dict


def test_globals_event_from_dict():
    """Test the from_dict method of GlobalsEvent."""
    data = {
        "old": {"key": "old_value"},
        "new": {"key": "new_value"},
    }
    event = GlobalsEvent.from_dict(data)
    assert event.old == {"key": "old_value"}
    assert event.new == {"key": "new_value"}

    # Test with no old or new values
    event_no_values = GlobalsEvent.from_dict({})
    assert event_no_values.old is None
    assert event_no_values.new is None