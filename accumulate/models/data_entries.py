# accumulate-python-client\accumulate\models\data_entries.py

import hashlib
from typing import List, Union
from accumulate.models.enums import DataEntryType
print(f"DEBUG: DataEntryType Enum: {list(DataEntryType)}")

class DataEntry:
    """Base class for data entries."""

    def __init__(self, data: List[bytes]):
        """
        Initialize a data entry.

        :param data: List of byte arrays representing the data.
        """
        self.data = data

    def type(self) -> int:
        """
        Return the type of the data entry.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Type method must be implemented by subclasses.")

    def get_data(self) -> List[bytes]:
        """
        Return the raw data of the entry.
        """
        return self.data

    def hash(self) -> bytes:
        """
        Return the hash of the data entry.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Hash method must be implemented by subclasses.")

    def marshal(self) -> bytes:
        """
        Serialize the DataEntry to bytes.
        """
        # Serialize the type as the first byte
        type_byte = self.type().to_bytes(1, "big")
        # Serialize the number of chunks
        chunk_count = len(self.data).to_bytes(2, "big")
        # Serialize each data chunk (length-prefixed)
        serialized_chunks = b"".join(len(chunk).to_bytes(4, "big") + chunk for chunk in self.data)
        return type_byte + chunk_count + serialized_chunks

    @classmethod
    def unmarshal(cls, data: bytes) -> "DataEntry":
        print(f"DEBUG: Starting unmarshal with data: {data}")
        if len(data) < 3:
            raise ValueError("Data too short to unmarshal: must include type and chunk count.")

        type_byte = data[0]
        print(f"DEBUG: Parsed type_byte: {type_byte}")
        chunk_count = int.from_bytes(data[1:3], "big")
        print(f"DEBUG: Parsed chunk_count: {chunk_count}")
        
        offset = 3
        chunks = []
        for _ in range(chunk_count):
            if offset + 4 > len(data):
                raise ValueError(f"Data too short to read chunk length at offset {offset}.")
            
            chunk_length = int.from_bytes(data[offset:offset + 4], "big")
            offset += 4
            
            if offset + chunk_length > len(data):
                raise ValueError(f"Data too short to read chunk at offset {offset}, expected length {chunk_length}.")
            
            chunk = data[offset:offset + chunk_length]
            offset += chunk_length
            chunks.append(chunk)

        print(f"DEBUG: Parsed chunks: {chunks}")

        if type_byte == DataEntryType.ACCUMULATE.value:
            return AccumulateDataEntry(chunks)
        elif type_byte == DataEntryType.DOUBLE_HASH.value:
            return DoubleHashDataEntry(chunks)
        else:
            raise ValueError(f"Unknown DataEntry type: {type_byte}")




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
        # Serialize the type as the first byte
        type_byte = self.type().value.to_bytes(1, "big")  # Use `.value` for enum
        # Serialize the number of chunks
        chunk_count = len(self.data).to_bytes(2, "big")
        # Serialize each data chunk (length-prefixed)
        serialized_chunks = b"".join(len(chunk).to_bytes(4, "big") + chunk for chunk in self.data)
        return type_byte + chunk_count + serialized_chunks



class DoubleHashDataEntry(DataEntry):
    """Represents a double-hash data entry."""

    def type(self) -> DataEntryType:
        return DataEntryType.DOUBLE_HASH

    def hash(self) -> bytes:
        hasher = hashlib.sha256()
        for chunk in self.data:
            hasher.update(chunk)
        merkle_root = hasher.digest()
        return hashlib.sha256(merkle_root).digest()


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
