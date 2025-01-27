# accumulate-python-client\tests\test_utils\test_union.py

import pytest
import json
from accumulate.utils.union import UnionValue


def test_union_value_initialization():
    """Test initialization with various types."""
    uv = UnionValue("test")
    assert uv.value == "test"

    uv = UnionValue(b"bytes")
    assert uv.value == b"bytes"

    uv = UnionValue(123)
    assert uv.value == 123

    uv = UnionValue(123.45)
    assert uv.value == 123.45

    uv = UnionValue(None)
    assert uv.value is None


def test_union_value_marshal_binary():
    """Test binary serialization."""
    uv = UnionValue("string")
    assert uv.marshal_binary() == b"string"

    uv = UnionValue(123)
    assert uv.marshal_binary() == b"123"

    uv = UnionValue(123.45)
    assert uv.marshal_binary() == b"123.45"

    uv = UnionValue(b"bytes")
    assert uv.marshal_binary() == b"bytes"

    with pytest.raises(ValueError):
        uv = UnionValue({"unsupported": object()})
        uv.marshal_binary()


def test_union_value_unmarshal_binary():
    """Test binary deserialization."""
    uv = UnionValue()
    uv.unmarshal_binary(b"binary")
    assert uv.value == b"binary"


def test_union_value_marshal_json():
    """Test JSON serialization."""
    uv = UnionValue("string")
    assert uv.marshal_json() == '"string"'

    uv = UnionValue(123)
    assert uv.marshal_json() == "123"

    uv = UnionValue(123.45)
    assert uv.marshal_json() == "123.45"

    uv = UnionValue(None)
    assert uv.marshal_json() == "null"

    with pytest.raises(ValueError):
        uv = UnionValue({"unsupported": object()})
        uv.marshal_json()


def test_union_value_unmarshal_json():
    """Test JSON deserialization."""
    uv = UnionValue()
    uv.unmarshal_json('"json"')
    assert uv.value == "json"

    uv.unmarshal_json("123")
    assert uv.value == 123

    uv.unmarshal_json("123.45")
    assert uv.value == 123.45

    uv.unmarshal_json("null")
    assert uv.value is None

    with pytest.raises(ValueError):
        uv.unmarshal_json("invalid_json")


def test_union_value_copy():
    """Test creating a copy of UnionValue."""
    uv = UnionValue("test")
    uv_copy = uv.copy()
    assert uv_copy.value == uv.value
    assert uv_copy is not uv


def test_union_value_equality():
    """Test equality between UnionValue instances."""
    uv1 = UnionValue("test")
    uv2 = UnionValue("test")
    uv3 = UnionValue("different")

    assert uv1 == uv2
    assert uv1 != uv3
    assert uv1 != "test"  # Different type


def test_union_value_hash():
    """Test hashing of UnionValue."""
    uv = UnionValue("test")
    assert isinstance(hash(uv), int)


def test_union_value_repr():
    """Test string representation of UnionValue."""
    uv = UnionValue("test")
    assert repr(uv) == 'UnionValue(value=\'test\')'
