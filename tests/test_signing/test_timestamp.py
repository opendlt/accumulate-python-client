# accumulate-python-client\tests\test_signing\test_timestamp.py 

import pytest
from accumulate.signing.timestamp import TimestampFromValue, TimestampFromVariable, Timestamp

# Test for the abstract base class Timestamp
def test_abstract_timestamp():
    class DummyTimestamp(Timestamp):
        def get(self):
            return 123

    dummy = DummyTimestamp()
    assert dummy.get() == 123

    # Ensure instantiation of abstract class raises an error
    with pytest.raises(TypeError):
        Timestamp()


# Tests for TimestampFromValue
def test_timestamp_from_value_valid():
    ts = TimestampFromValue(100)
    assert ts.get() == 100

def test_timestamp_from_value_zero():
    ts = TimestampFromValue(0)
    assert ts.get() == 0

def test_timestamp_from_value_negative():
    with pytest.raises(ValueError, match="Timestamp value must be non-negative"):
        TimestampFromValue(-1)


# Tests for TimestampFromVariable
def test_timestamp_from_variable_default():
    ts = TimestampFromVariable()
    assert ts.get() == 1
    assert ts.get() == 2

def test_timestamp_from_variable_custom_initial():
    ts = TimestampFromVariable(10)
    assert ts.get() == 11
    assert ts.get() == 12

def test_timestamp_from_variable_negative_initial():
    with pytest.raises(ValueError, match="Initial timestamp value must be non-negative"):
        TimestampFromVariable(-1)

def test_timestamp_from_variable_reset():
    ts = TimestampFromVariable(10)
    ts.get()  # Increments to 11
    ts.reset(5)
    assert ts.get() == 6

def test_timestamp_from_variable_reset_zero():
    ts = TimestampFromVariable(10)
    ts.get()  # Increments to 11
    ts.reset(0)
    assert ts.get() == 1

def test_timestamp_from_variable_reset_negative():
    ts = TimestampFromVariable()
    with pytest.raises(ValueError, match="Reset value must be non-negative"):
        ts.reset(-1)

def test_timestamp_from_variable_thread_safety():
    """
    Simulate concurrent access to ensure thread safety.
    """
    import threading

    ts = TimestampFromVariable(0)
    results = []

    def increment_and_store():
        for _ in range(1000):
            results.append(ts.get())

    threads = [threading.Thread(target=increment_and_store) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Check that all timestamps are unique and incremented correctly
    assert len(results) == 10000
    assert len(set(results)) == 10000
    assert max(results) == 10000
