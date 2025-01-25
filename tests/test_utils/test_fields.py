# C:\Accumulate_Stuff\accumulate-python-client\tests\test_utils\test_fields.py

import pytest
from datetime import datetime, timedelta
from accumulate.utils.fields import (
    Field, IntField, StringField, BoolField, DateTimeField, FloatField,
    ReadOnlyAccessor, DurationField, TimeAccessor
)


# Test Base Field Class
def test_field_base():
    field = Field(name="test_field", required=True, omit_empty=True)
    assert field.name == "test_field"
    assert field.required is True
    assert field.omit_empty is True

    # Test is_empty method
    assert field.is_empty(None) is True
    assert field.is_empty("") is True
    assert field.is_empty([]) is True
    assert field.is_empty("value") is False

    # Test to_json method
    assert field.to_json(None) is None
    assert field.to_json("value") == "value"

    # Test from_json method
    instance = type("MockInstance", (object,), {})()
    field.from_json({"test_field": "value"}, instance)
    assert instance.test_field == "value"


# Test IntField
def test_int_field():
    field = IntField(name="int_field", omit_empty=True)
    assert field.to_json(0) is None
    assert field.to_json(123) == 123


# Test StringField
def test_string_field():
    field = StringField(name="string_field", omit_empty=True)
    assert field.to_json("") is None
    assert field.to_json("test") == "test"


# Test BoolField
def test_bool_field():
    field = BoolField(name="bool_field", omit_empty=True)
    assert field.to_json(False) is None
    assert field.to_json(True) is True


# Test DateTimeField
def test_datetime_field():
    field = DateTimeField(name="datetime_field", omit_empty=True)
    dt = datetime(2025, 1, 1, 12, 0, 0)
    assert field.to_json(None) is None
    assert field.to_json(dt) == dt.isoformat()

    # Test from_json with valid data
    instance = type("MockInstance", (object,), {})()
    field.from_json({"datetime_field": dt.isoformat()}, instance)
    assert instance.datetime_field == dt

    # Test from_json with invalid data
    with pytest.raises(ValueError):
        field.from_json({"datetime_field": "invalid_date"}, instance)


# Test FloatField
def test_float_field():
    field = FloatField(name="float_field", omit_empty=True)
    assert field.to_json(0.0) is None
    assert field.to_json(123.45) == 123.45


# Test ReadOnlyAccessor
def test_read_only_accessor():
    class MockObject:
        def __init__(self, value):
            self.value = value

    obj = MockObject(123)
    accessor = ReadOnlyAccessor(lambda o: o.value)

    assert accessor.is_empty(obj) is False
    assert accessor.equal(MockObject(123), MockObject(123)) is True
    assert accessor.equal(MockObject(123), MockObject(456)) is False
    assert accessor.to_json(obj) == 123

    with pytest.raises(ValueError):
        accessor.write_to(MockObject([1, 2, 3]))

    with pytest.raises(NotImplementedError):
        accessor.copy_to(None, None)

    with pytest.raises(NotImplementedError):
        accessor.read_from(None, None)

    with pytest.raises(NotImplementedError):
        accessor.from_json(None, None)


# Test DurationField
def test_duration_field():
    field = DurationField(name="duration_field", omit_empty=True)
    duration = timedelta(seconds=3600, microseconds=123456)

    # Test to_json
    json_data = field.to_json(duration)
    assert json_data == {"seconds": 3600, "nanoseconds": 123456000}

    # Test from_json
    instance = type("MockInstance", (object,), {})()
    field.from_json({"duration_field": json_data}, instance)
    assert instance.duration_field == duration

    # Test is_empty
    assert field.is_empty(timedelta(0)) is True
    assert field.is_empty(duration) is False



# Test TimeAccessor
def test_time_accessor():
    class MockObject:
        def __init__(self, value):
            self.value = value

    dt = datetime(2025, 1, 1, 12, 0, 0)
    obj = MockObject(dt)
    accessor = TimeAccessor(lambda o: o.value)

    assert accessor.to_json(obj) == dt.isoformat()
    assert accessor.is_empty(MockObject(None)) is True
    assert accessor.is_empty(obj) is False
