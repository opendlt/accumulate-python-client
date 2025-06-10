# accumulate-python-client\tests\test_utils\test_fields.py

import pytest
from datetime import datetime, timedelta
from accumulate.utils.fields import (
    Field, IntField, StringField, BoolField, DateTimeField, FloatField,
    ReadOnlyAccessor, DurationField, TimeAccessor
)


# --- Field & Subclasses ---

def test_field_base_and_from_to_json():
    field = Field(name="test", required=True, omit_empty=True)
    assert field.name == "test" and field.required
    # is_empty
    assert field.is_empty(None)
    assert field.is_empty("") and field.is_empty([])
    assert not field.is_empty("x")
    # to_json / omit_empty
    assert field.to_json(None) is None
    assert field.to_json("val") == "val"
    # from_json
    inst = type("X", (), {})()
    field.from_json({"test": 123}, inst)
    assert inst.test == 123

def test_int_string_bool_float_fields():
    assert IntField("i", omit_empty=True).to_json(0) is None
    assert IntField("i", omit_empty=True).to_json(5) == 5

    assert StringField("s", omit_empty=True).to_json("") is None
    assert StringField("s", omit_empty=True).to_json("hi") == "hi"

    assert BoolField("b", omit_empty=True).to_json(False) is None
    assert BoolField("b", omit_empty=True).to_json(True) is True

    assert FloatField("f", omit_empty=True).to_json(0.0) is None
    assert FloatField("f", omit_empty=True).to_json(1.23) == 1.23

def test_datetime_field_roundtrip_and_errors():
    f = DateTimeField("dt", omit_empty=True)
    dt = datetime(2025,1,1,12,0,0)
    # to_json
    assert f.to_json(None) is None
    assert f.to_json(dt) == dt.isoformat()
    # from_json
    inst = type("X", (), {})()
    f.from_json({"dt": dt.isoformat()}, inst)
    assert inst.dt == dt
    # bad format
    with pytest.raises(ValueError):
        f.from_json({"dt": "not-a-date"}, inst)


# --- DurationField ---

def test_duration_field_to_json_and_empty():
    d1 = DurationField("d", omit_empty=True)
    d = timedelta(days=1, seconds=366, microseconds=500)
    out = d1.to_json(d)
    assert out["seconds"] == 86400 + 366 and out["nanoseconds"] == 500_000
    # omit_empty should drop 0
    assert d1.to_json(timedelta(0)) is None

    # when omit_empty=False
    d2 = DurationField("d", omit_empty=False)
    zero_dict = d2.to_json(timedelta(0))
    assert zero_dict == {"seconds": 0, "nanoseconds": 0}

    # from_json round-trip
    inst = type("X", (), {})()
    d2.from_json({"d": zero_dict}, inst)
    assert inst.d == timedelta(0)
    # is_empty
    assert d1.is_empty(timedelta(0))
    assert not d1.is_empty(d)


# --- ReadOnlyAccessor.to_json branches ---

def test_readonly_to_json_primitives():
    obj = type("O", (), {"val": 99})()
    acc = ReadOnlyAccessor(lambda o: o.val)
    assert acc.to_json(obj) == 99

def test_readonly_to_json_with_to_dict():
    class HasToDict:
        def to_dict(self):
            return {"foo": "bar"}
    obj = type("O", (), {"val": HasToDict()})()
    acc = ReadOnlyAccessor(lambda o: o.val)
    assert acc.to_json(obj) == {"foo": "bar"}

def test_readonly_to_json_with_dict_only():
    class HasDictOnly:
        def __init__(self):
            self.a = 1
            self.b = "two"
    obj = type("O", (), {"val": HasDictOnly()})()
    acc = ReadOnlyAccessor(lambda o: o.val)
    assert acc.to_json(obj) == {"a": 1, "b": "two"}

def test_readonly_to_json_error():
    class NoSlots:
        __slots__ = ()
    obj = type("O", (), {"val": NoSlots()})()
    acc = ReadOnlyAccessor(lambda o: o.val)
    with pytest.raises(ValueError, match="Cannot serialize value of type NoSlots"):
        acc.to_json(obj)


# --- ReadOnlyAccessor.write_to branches ---

def test_readonly_write_to_primitives():
    cases = [
        (42, b"42"),
        (3.14, b"3.14"),
        ("hello", b"hello"),
        (b"\x00\xff", b"\x00\xff"),
    ]
    for val, expected in cases:
        obj = type("O", (), {"val": val})()
        acc = ReadOnlyAccessor(lambda o: o.val)
        assert acc.write_to(obj) == expected

def test_readonly_write_to_error():
    obj = type("O", (), {"val": object()})()
    acc = ReadOnlyAccessor(lambda o: o.val)
    with pytest.raises(ValueError, match="Cannot write value of type object to binary"):
        acc.write_to(obj)


# --- ReadOnlyAccessor immutable methods raise ---

def test_readonly_immutable_methods():
    acc = ReadOnlyAccessor(lambda o: None)
    with pytest.raises(NotImplementedError):
        acc.copy_to(None, None)
    with pytest.raises(NotImplementedError):
        acc.read_from(b"", None)
    with pytest.raises(NotImplementedError):
        acc.from_json(None, None)


# --- TimeAccessor ---

def test_time_accessor():
    class M:
        def __init__(self, v): self.v = v
    dt = datetime(2025,1,1,12,0,0)
    acc = TimeAccessor(lambda o: o.v)
    assert acc.to_json(M(dt)) == dt.isoformat()
    assert acc.to_json(M(None)) is None
    assert acc.is_empty(M(None))
    assert not acc.is_empty(M(dt))
