# accumulate-python-client\accumulate\models\data_entries.py

from asyncio.log import logger
import hashlib
import io
from typing import List, Union
from accumulate.models.enums import DataEntryType
from accumulate.utils.encoding import bytes_marshal_binary, encode_uvarint, read_uvarint, unmarshal_bytes

class DataEntry:
    """Base class for data entries."""

    def __init__(self, data: List[bytes]):
        if not isinstance(data, list) or not all(isinstance(d, bytes) for d in data):
            raise TypeError("Data must be a list of byte arrays.")
        self.data = data

    def type(self) -> DataEntryType:
        """Return the data entry type (must be implemented by subclasses)."""
        raise NotImplementedError("Type method must be implemented by subclasses.")

    def get_data(self) -> List[bytes]:
        """Return the raw data of the entry."""
        return self.data

    def hash(self) -> bytes:
        """Return the hash of the data entry (must be implemented by subclasses)."""
        raise NotImplementedError("Hash method must be implemented by subclasses.")

    def marshal(self) -> bytes:
        """
        Serialize the DataEntry to bytes.
         FIX: Ensure the correct entry encoding.
        """
        type_byte = encode_uvarint(self.type().value)  #  Correctly encode DataEntryType
        serialized_chunks = b"".join(bytes_marshal_binary(chunk) for chunk in self.data)

        return type_byte + serialized_chunks


    @classmethod
    def unmarshal(cls, data: bytes) -> "DataEntry":
        """Deserialize a data entry from bytes."""
        logger.debug(f" Unmarshaling DataEntry")

        reader = io.BytesIO(data)

        #  Step 1: Read **DataEntryType**
        type_value = read_uvarint(reader)
        if type_value not in {DataEntryType.ACCUMULATE.value, DataEntryType.DOUBLE_HASH.value}:
            raise ValueError(f"Unknown DataEntryType: {type_value}")

        #  Step 2: Read **Chunk Count**
        chunk_count = read_uvarint(reader)

        #  Step 3: Read **Each Data Chunk**
        chunks = [unmarshal_bytes(reader) for _ in range(chunk_count)]

        #  Step 4: Return the correct DataEntry subclass
        if type_value == DataEntryType.ACCUMULATE.value:
            return AccumulateDataEntry(chunks)
        elif type_value == DataEntryType.DOUBLE_HASH.value:
            return DoubleHashDataEntry(chunks)
        else:
            raise ValueError(f"Unexpected DataEntryType: {type_value}")


class AccumulateDataEntry(DataEntry):
    """Represents a single-hash data entry."""

    def type(self) -> DataEntryType:
        return DataEntryType.ACCUMULATE

    def hash(self) -> bytes:
        hasher = hashlib.sha256()
        for chunk in self.data:
            hasher.update(chunk)
        return hasher.digest()

    def marshal(self) -> bytes:
        """
        Serialize the DataEntry to bytes.
        """
        type_byte = encode_uvarint(2)
        chunk_count = encode_uvarint(len(self.data))  #  Use uvarint encoding for chunk count
        serialized_chunks = b"".join(bytes_marshal_binary(chunk) for chunk in self.data)
        
        return type_byte + chunk_count + serialized_chunks

    def to_dict(self) -> dict:
        """
         Convert AccumulateDataEntry to a JSON-serializable dictionary.
        """
        return {
            "type": "accumulate",  #  Ensure type matches expected JSON output
            "data": [chunk.hex() for chunk in self.data]  #  Convert bytes to hex
        }


class DoubleHashDataEntry(DataEntry):
    """Represents a double-hash data entry (Used in Go JSON)."""

    def type(self) -> DataEntryType:
        """Return the DataEntryType for double-hash entries."""
        return DataEntryType.DOUBLE_HASH

    def hash(self) -> bytes:
        """Compute the double SHA-256 hash (Merkle root of the data)."""
        hasher = hashlib.sha256()
        for chunk in self.data:
            hasher.update(chunk)
        merkle_root = hasher.digest()
        return hashlib.sha256(merkle_root).digest()

    def marshal(self) -> bytes:
        """
        Serialize the DataEntry to bytes.
         FIX: Ensure the correct entry encoding.
        """
        entry_type = encode_uvarint(1)  #  Entry field identifier is always `01`
        type_value = encode_uvarint(self.type().value)  #  Encode `03` for doubleHash
        data_field = encode_uvarint(2)  #  Data field identifier is always `02`
        
        serialized_chunks = b"".join(bytes_marshal_binary(chunk) for chunk in self.data)

        return entry_type + type_value + data_field + serialized_chunks  #  Fix order!


    def to_dict(self) -> dict:
        """
         Convert DoubleHashDataEntry to a JSON-serializable dictionary.
        """
        return {
            "type": "doubleHash",  #  Ensure type matches expected JSON output
            "data": [chunk.hex() for chunk in self.data]  #  Convert bytes to hex
        }




class DataEntryUtils:
    """Utility functions for data entries."""

    TRANSACTION_SIZE_MAX = 20480  # Maximum transaction size
    FEE_DATA_UNIT = 256          # Fee unit size

    @staticmethod
    def check_data_entry_size(entry: DataEntry) -> int:
        """
        Validate the size of the data entry.

        :param entry: The data entry to check.
        :return: The size of the marshaled data entry in bytes.
        :raises ValueError: If the entry is empty or exceeds the size limit.
        """
        size = sum(len(chunk) for chunk in entry.get_data())
        if size > DataEntryUtils.TRANSACTION_SIZE_MAX:
            raise ValueError(f"Data exceeds {DataEntryUtils.TRANSACTION_SIZE_MAX} byte entry limit.")
        if size <= 0:
            raise ValueError("No data provided for WriteData.")
        return size

    @staticmethod
    def calculate_data_entry_cost(entry: DataEntry, fee_data: int) -> int:
        """
        Calculate the cost of writing a data entry.

        :param entry: The data entry to calculate the cost for.
        :param fee_data: The base fee multiplier for data entries.
        :return: The cost in credits.
        """
        size = DataEntryUtils.check_data_entry_size(entry)
        return fee_data * ((size // DataEntryUtils.FEE_DATA_UNIT) + 1)
