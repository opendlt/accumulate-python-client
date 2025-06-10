# accumulate-python-client\tests\test_utils\test_protocols.py

import pytest
from typing import Any, BinaryIO
from accumulate.utils.protocols import BinaryValue, UnionValue

# --- Improper Mock for Testing Abstract Methods ---
class ImproperBinaryValue(BinaryValue):
    """Improper implementation to test abstract methods."""
    pass


class ImproperUnionValue(UnionValue):
    """Improper implementation to test abstract methods."""
    pass


# --- Tests for Abstract Methods ---
def test_binary_value_abstract_methods():
    """Ensure BinaryValue's abstract methods raise NotImplementedError."""
    obj = ImproperBinaryValue()  # Improper class that does not implement methods

    with pytest.raises(NotImplementedError, match="marshal_binary must be implemented"):
        obj.marshal_binary()

    with pytest.raises(NotImplementedError, match="unmarshal_binary must be implemented"):
        obj.unmarshal_binary(b"")

    with pytest.raises(NotImplementedError, match="copy_as_interface must be implemented"):
        obj.copy_as_interface()

    with pytest.raises(NotImplementedError, match="unmarshal_binary_from must be implemented"):
        obj.unmarshal_binary_from(None)  # `None` is used as we are testing the raise condition


def test_union_value_abstract_methods():
    """Ensure UnionValue's abstract methods raise NotImplementedError."""
    obj = ImproperUnionValue()  # Improper class that does not implement methods

    with pytest.raises(NotImplementedError, match="unmarshal_fields_from must be implemented"):
        obj.unmarshal_fields_from(None)  # `None` is used as we are testing the raise condition
