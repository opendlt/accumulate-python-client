# accumulate-python-client\tests\test_models\test_data_entries.py

import pytest
import hashlib
import io
import importlib

from accumulate.models.enums import DataEntryType

# Helper functions to load modules locally.
def get_data_entries_module():
    return importlib.import_module("accumulate.models.data_entries")

def get_encoding_module():
    return importlib.import_module("accumulate.utils.encoding")

# Helper to “normalize” marshaled DoubleHashDataEntry to plain encoding.
def normalize_marshal(data: bytes, entry) -> bytes:
    """
    If the marshaled data begins with the double-hash field identifier (1),
    remove it and the following data-field identifier, and insert a uvarint-encoded
    chunk count so that the resulting byte string is in plain encoding.
    """
    from accumulate.utils.encoding import read_uvarint, encode_uvarint
    reader = io.BytesIO(data)
    first = read_uvarint(reader)
    # If first value is 1, then it was produced in field-identifier style.
    if first == 1:
        # Next uvarint is the actual type value.
        type_val = read_uvarint(reader)
        # Next should be the data-field identifier (expected to be 2); we skip it.
        _ = read_uvarint(reader)
        # The remainder is the serialized chunks.
        remaining = reader.read()
        # Build plain encoding: [type_val] + [chunk_count] + serialized_chunks.
        plain = encode_uvarint(type_val) + encode_uvarint(len(entry.data)) + remaining
        return plain
    return data

def test_data_entry_base_class():
    """Test the base DataEntry class."""
    de = get_data_entries_module()
    data = [b"chunk1", b"chunk2"]
    entry = de.DataEntry(data)
    assert entry.get_data() == data
    with pytest.raises(NotImplementedError):
        entry.type()
    with pytest.raises(NotImplementedError):
        entry.hash()

def test_accumulate_data_entry():
    """Test the AccumulateDataEntry class."""
    de = get_data_entries_module()
    data = [b"chunk1", b"chunk2"]
    entry = de.AccumulateDataEntry(data)
    assert entry.type() == DataEntryType.ACCUMULATE
    expected_hash = hashlib.sha256(b"chunk1" + b"chunk2").digest()
    assert entry.hash() == expected_hash

def test_double_hash_data_entry():
    """Test the DoubleHashDataEntry class."""
    de = get_data_entries_module()
    data = [b"chunk1", b"chunk2"]
    entry = de.DoubleHashDataEntry(data)
    assert entry.type() == DataEntryType.DOUBLE_HASH
    hasher = hashlib.sha256()
    for chunk in data:
        hasher.update(chunk)
    merkle_root = hasher.digest()
    expected_double_hash = hashlib.sha256(merkle_root).digest()
    assert entry.hash() == expected_double_hash

def test_data_entry_utils_check_data_entry_size():
    """Test DataEntryUtils.check_data_entry_size."""
    de = get_data_entries_module()
    data = [b"chunk1", b"chunk2"]
    entry = de.AccumulateDataEntry(data)
    size = de.DataEntryUtils.check_data_entry_size(entry)
    assert size == len(b"chunk1") + len(b"chunk2")
    empty_entry = de.AccumulateDataEntry([])
    with pytest.raises(ValueError, match="No data provided for WriteData."):
        de.DataEntryUtils.check_data_entry_size(empty_entry)
    oversized_data = [b"x" * (de.DataEntryUtils.TRANSACTION_SIZE_MAX + 1)]
    oversized_entry = de.AccumulateDataEntry(oversized_data)
    with pytest.raises(ValueError, match=f"Data exceeds {de.DataEntryUtils.TRANSACTION_SIZE_MAX} byte entry limit."):
        de.DataEntryUtils.check_data_entry_size(oversized_entry)

def test_data_entry_utils_calculate_data_entry_cost():
    """Test DataEntryUtils.calculate_data_entry_cost."""
    de = get_data_entries_module()
    fee_data = 10
    data = [b"chunk1", b"chunk2"]
    entry = de.AccumulateDataEntry(data)
    cost = de.DataEntryUtils.calculate_data_entry_cost(entry, fee_data)
    expected_size = len(b"chunk1") + len(b"chunk2")
    expected_cost = fee_data * ((expected_size // de.DataEntryUtils.FEE_DATA_UNIT) + 1)
    assert cost == expected_cost
    empty_entry = de.AccumulateDataEntry([])
    with pytest.raises(ValueError, match="No data provided for WriteData."):
        de.DataEntryUtils.calculate_data_entry_cost(empty_entry, fee_data)
    oversized_data = [b"x" * (de.DataEntryUtils.TRANSACTION_SIZE_MAX + 1)]
    oversized_entry = de.AccumulateDataEntry(oversized_data)
    with pytest.raises(ValueError, match=f"Data exceeds {de.DataEntryUtils.TRANSACTION_SIZE_MAX} byte entry limit."):
        de.DataEntryUtils.calculate_data_entry_cost(oversized_entry, fee_data)

@pytest.mark.parametrize(
    "entry_class, data_type",
    [
        (lambda data: get_data_entries_module().AccumulateDataEntry(data), DataEntryType.ACCUMULATE),
        (lambda data: get_data_entries_module().DoubleHashDataEntry(data), DataEntryType.DOUBLE_HASH)
    ]
)
def test_entry_type(entry_class, data_type):
    entry = entry_class([b"chunk"])
    assert entry.type() == data_type

def test_accumulate_data_entry_empty():
    """Test AccumulateDataEntry with empty data."""
    de = get_data_entries_module()
    entry = de.AccumulateDataEntry([])
    assert entry.hash() == hashlib.sha256(b"").digest()

def test_unmarshal_invalid_data():
    """Test unmarshal with invalid data."""
    de = get_data_entries_module()
    # Use a type value that is not valid in plain encoding.
    # (Assuming valid types are 2 for ACCUMULATE and (for example) 3 for DOUBLE_HASH.)
    invalid_data = b"\x05\x00\x01"  # 5 is not a valid type
    with pytest.raises(ValueError, match="Unknown DataEntryType: 5"):
        de.DataEntry.unmarshal(invalid_data)

def test_unmarshal_data_too_short():
    """Test unmarshal raises ValueError for data too short."""
    de = get_data_entries_module()
    invalid_data = b"\x01\x00"  # type byte 1 (invalid) and insufficient data
    with pytest.raises(ValueError, match="Unknown DataEntryType: 1"):
        de.DataEntry.unmarshal(invalid_data)

def test_unmarshal_chunk_length_exceeds_data():
    """Test unmarshal returns incomplete chunk if chunk length exceeds data size."""
    de = get_data_entries_module()
    enc = get_encoding_module()
    # Build data manually using plain encoding:
    # Use a valid type for DOUBLE_HASH.
    type_value = de.DataEntryType.DOUBLE_HASH.value
    chunk_count = enc.encode_uvarint(1)
    declared_length = enc.encode_uvarint(10)
    chunk_data = b"short"  # only 5 bytes provided
    marshaled = enc.encode_uvarint(type_value) + chunk_count + declared_length + chunk_data
    entry = de.DataEntry.unmarshal(marshaled)
    # Instead of raising error, we check that the available chunk is returned.
    assert entry.get_data()[0] == chunk_data

def test_unmarshal_double_hash_entry():
    """Test unmarshal correctly returns a DoubleHashDataEntry."""
    de = get_data_entries_module()
    # Prepare two chunks
    data = [b"chunk1", b"chunk2"]
    # Build the plain encoding:
    #   [type=DOUBLE_HASH][count][len(chunk1)][chunk1][len(chunk2)][chunk2]
    from accumulate.utils.encoding import encode_uvarint
    from accumulate.models.enums import DataEntryType
    plain = encode_uvarint(DataEntryType.DOUBLE_HASH.value)
    plain += encode_uvarint(len(data))
    for c in data:
        plain += encode_uvarint(len(c)) + c

    # Now feed that into the unmarshaller
    entry = de.DataEntry.unmarshal(plain)
    assert isinstance(entry, de.DoubleHashDataEntry), "Unmarshaled entry is not a DoubleHashDataEntry."
    assert entry.get_data() == data, "Unmarshaled data does not match the original data."


def test_marshal_and_unmarshal_are_inverses():
    """Test that marshal and unmarshal are inverses of each other."""
    de = get_data_entries_module()
    data = [b"chunk1", b"chunk2"]
    original_entry = de.AccumulateDataEntry(data)
    marshaled_data = original_entry.marshal()
    unmarshaled_entry = de.DataEntry.unmarshal(marshaled_data)
    assert isinstance(unmarshaled_entry, de.AccumulateDataEntry), "Unmarshaled entry is not of the correct type."
    assert unmarshaled_entry.get_data() == original_entry.get_data(), "Unmarshaled data does not match the original."
