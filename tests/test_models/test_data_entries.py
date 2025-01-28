# accumulate-python-client\tests\test_models\test_data_entries.py

import pytest
import hashlib
from accumulate.models.data_entries import (
    DataEntry,
    AccumulateDataEntry,
    DoubleHashDataEntry,
    DataEntryUtils,
)
from accumulate.models.enums import DataEntryType


def test_data_entry_base_class():
    """Test the base DataEntry class."""
    data = [b"chunk1", b"chunk2"]
    entry = DataEntry(data)

    # Test get_data
    assert entry.get_data() == data

    # Test type and hash raise NotImplementedError
    with pytest.raises(NotImplementedError):
        entry.type()
    with pytest.raises(NotImplementedError):
        entry.hash()


def test_accumulate_data_entry():
    """Test the AccumulateDataEntry class."""
    data = [b"chunk1", b"chunk2"]
    entry = AccumulateDataEntry(data)

    # Test type
    assert entry.type() == DataEntryType.ACCUMULATE

    # Test hash
    expected_hash = hashlib.sha256(b"chunk1" + b"chunk2").digest()
    assert entry.hash() == expected_hash


def test_double_hash_data_entry():
    """Test the DoubleHashDataEntry class."""
    data = [b"chunk1", b"chunk2"]
    entry = DoubleHashDataEntry(data)

    # Test type
    assert entry.type() == DataEntryType.DOUBLE_HASH

    # Test hash
    hasher = hashlib.sha256()
    hasher.update(b"chunk1")
    hasher.update(b"chunk2")
    merkle_root = hasher.digest()
    expected_double_hash = hashlib.sha256(merkle_root).digest()
    assert entry.hash() == expected_double_hash


def test_data_entry_utils_check_data_entry_size():
    """Test DataEntryUtils.check_data_entry_size."""
    # Test valid entry
    data = [b"chunk1", b"chunk2"]
    entry = AccumulateDataEntry(data)
    size = DataEntryUtils.check_data_entry_size(entry)
    assert size == len(b"chunk1") + len(b"chunk2")

    # Test empty entry
    empty_entry = AccumulateDataEntry([])
    with pytest.raises(ValueError, match="No data provided for WriteData."):
        DataEntryUtils.check_data_entry_size(empty_entry)

    # Test oversized entry
    oversized_data = [b"x" * (DataEntryUtils.TRANSACTION_SIZE_MAX + 1)]
    oversized_entry = AccumulateDataEntry(oversized_data)
    with pytest.raises(ValueError, match=f"Data exceeds {DataEntryUtils.TRANSACTION_SIZE_MAX} byte entry limit."):
        DataEntryUtils.check_data_entry_size(oversized_entry)


def test_data_entry_utils_calculate_data_entry_cost():
    """Test DataEntryUtils.calculate_data_entry_cost."""
    fee_data = 10  # Arbitrary fee multiplier

    # Test valid entry
    data = [b"chunk1", b"chunk2"]
    entry = AccumulateDataEntry(data)
    cost = DataEntryUtils.calculate_data_entry_cost(entry, fee_data)
    expected_size = len(b"chunk1") + len(b"chunk2")
    expected_cost = fee_data * ((expected_size // DataEntryUtils.FEE_DATA_UNIT) + 1)
    assert cost == expected_cost

    # Test empty entry
    empty_entry = AccumulateDataEntry([])
    with pytest.raises(ValueError, match="No data provided for WriteData."):
        DataEntryUtils.calculate_data_entry_cost(empty_entry, fee_data)

    # Test oversized entry
    oversized_data = [b"x" * (DataEntryUtils.TRANSACTION_SIZE_MAX + 1)]
    oversized_entry = AccumulateDataEntry(oversized_data)
    with pytest.raises(ValueError, match=f"Data exceeds {DataEntryUtils.TRANSACTION_SIZE_MAX} byte entry limit."):
        DataEntryUtils.calculate_data_entry_cost(oversized_entry, fee_data)


@pytest.mark.parametrize(
    "entry_class, data_type",
    [(AccumulateDataEntry, DataEntryType.ACCUMULATE),
     (DoubleHashDataEntry, DataEntryType.DOUBLE_HASH)]
)
def test_entry_type(entry_class, data_type):
    entry = entry_class([b"chunk"])
    assert entry.type() == data_type


def test_accumulate_data_entry_empty():
    """Test AccumulateDataEntry with empty data."""
    entry = AccumulateDataEntry([])
    assert entry.hash() == hashlib.sha256(b"").digest()


def test_unmarshal_invalid_data():
    """Test unmarshal with invalid data."""
    invalid_data = b"\x03\x00\x01"  # Invalid type and incomplete chunk
    with pytest.raises(ValueError, match="Data too short to read chunk length at offset 3."):
        DataEntry.unmarshal(invalid_data)

    invalid_data = b"\x05\x00\x00"  # Invalid type_byte but sufficient data
    with pytest.raises(ValueError, match="Unknown DataEntry type: 5"):
        DataEntry.unmarshal(invalid_data)












def test_data_entry_marshal():
    """Test DataEntry marshal method."""
    data = [b"chunk1", b"chunk2"]
    entry = AccumulateDataEntry(data)

    # Marshal the entry
    marshaled_data = entry.marshal()

    # Expected marshaled result
    type_byte = DataEntryType.ACCUMULATE.value.to_bytes(1, "big")  # Use `.value` to get the integer representation
    chunk_count = len(data).to_bytes(2, "big")
    serialized_chunks = (
        len(data[0]).to_bytes(4, "big") + data[0] +
        len(data[1]).to_bytes(4, "big") + data[1]
    )
    expected_marshal = type_byte + chunk_count + serialized_chunks

    # Assert the marshaled data is as expected
    assert marshaled_data == expected_marshal, "Marshaled data does not match expected result."



def test_unmarshal_data_too_short():
    """Test unmarshal raises ValueError for short data."""
    invalid_data = b"\x01\x00"  # Too short for type and chunk count
    with pytest.raises(ValueError, match="Data too short to unmarshal: must include type and chunk count."):
        DataEntry.unmarshal(invalid_data)


def test_unmarshal_chunk_length_exceeds_data():
    """Test unmarshal raises ValueError when chunk length exceeds data size."""
    invalid_data = (
        DataEntryType.DOUBLE_HASH.value.to_bytes(1, "big") +  # Use `.value` to get the integer representation
        (1).to_bytes(2, "big") +  # One chunk
        (10).to_bytes(4, "big") +  # Chunk length of 10
        b"short"  # Actual chunk is shorter than declared length
    )
    with pytest.raises(ValueError, match="Data too short to read chunk at offset 7, expected length 10."):
        DataEntry.unmarshal(invalid_data)

def test_unmarshal_double_hash_entry():
    """Test unmarshal correctly returns a DoubleHashDataEntry."""
    data = [b"chunk1", b"chunk2"]
    marshaled_data = (
        DataEntryType.DOUBLE_HASH.value.to_bytes(1, "big") +  # Use `.value`
        len(data).to_bytes(2, "big") +
        b"".join(len(chunk).to_bytes(4, "big") + chunk for chunk in data)
    )

    # Unmarshal the data
    entry = DataEntry.unmarshal(marshaled_data)

    # Assert the entry is of the correct type
    assert isinstance(entry, DoubleHashDataEntry), "Unmarshaled entry is not a DoubleHashDataEntry."

    # Assert the data is correctly parsed
    assert entry.get_data() == data, "Unmarshaled data does not match the original data."


def test_marshal_and_unmarshal_are_inverses():
    """Test that marshal and unmarshal are inverses of each other."""
    data = [b"chunk1", b"chunk2"]
    original_entry = AccumulateDataEntry(data)

    # Marshal the entry
    marshaled_data = original_entry.marshal()

    # Unmarshal the marshaled data
    unmarshaled_entry = DataEntry.unmarshal(marshaled_data)

    # Assert the unmarshaled data matches the original
    assert isinstance(unmarshaled_entry, AccumulateDataEntry), "Unmarshaled entry is not of the correct type."
    assert unmarshaled_entry.get_data() == original_entry.get_data(), "Unmarshaled data does not match the original."
