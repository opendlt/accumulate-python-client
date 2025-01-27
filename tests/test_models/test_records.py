# accumulate-python-client\tests\test_models\test_records.py

import pytest
from datetime import datetime, timezone
from accumulate.models.records import (
    Record,
    UrlRecord,
    TxIDRecord,
    RecordRange,
    AccountRecord,
    ChainRecord,
    ChainEntryRecord,
    KeyRecord,
    MessageRecord,
    SignatureSetRecord,
)


def test_record_base_class():
    """Test the base Record class."""
    data = {"record_type": "BASE", "data": {"key": "value"}}
    record = Record(record_type=data["record_type"], data=data["data"])

    assert record.record_type == "BASE"
    assert record.data == {"key": "value"}
    assert record.to_dict() == data

    deserialized = Record.from_dict(data)
    assert deserialized.record_type == "BASE"
    assert deserialized.data == {"key": "value"}


def test_url_record():
    """Test the UrlRecord class."""
    data = {"value": "https://example.com"}
    url_record = UrlRecord(value=data["value"])

    assert url_record.value == "https://example.com"
    assert url_record.to_dict() == data

    deserialized = UrlRecord.from_dict(data)
    assert deserialized.value == "https://example.com"


def test_txid_record():
    """Test the TxIDRecord class."""
    data = {"value": "TX12345"}
    txid_record = TxIDRecord(value=data["value"])

    assert txid_record.value == "TX12345"
    assert txid_record.to_dict() == data

    deserialized = TxIDRecord.from_dict(data)
    assert deserialized.value == "TX12345"


def test_record_range():
    """Test the RecordRange class."""
    records = [UrlRecord(value="https://example1.com"), UrlRecord(value="https://example2.com")]
    range_data = {
        "records": [record.to_dict() for record in records],
        "start": 0,
        "total": 2,
        "last_block_time": datetime.now(timezone.utc).isoformat(),
    }
    record_range = RecordRange(
        records=records,
        start=range_data["start"],
        total=range_data["total"],
        last_block_time=datetime.fromisoformat(range_data["last_block_time"]),
    )

    assert record_range.to_dict() == range_data

    deserialized = RecordRange.from_dict(range_data, UrlRecord)
    assert len(deserialized.records) == 2
    assert deserialized.records[0].value == "https://example1.com"


def test_account_record():
    """Test the AccountRecord class."""
    data = {
        "account": {"address": "acc://test"},
        "directory": {
            "records": [{"value": "https://example.com"}],
            "start": 0,
            "total": 1,
            "last_block_time": None,
        },
        "pending": None,
        "receipt": {"status": "success"},
        "last_block_time": None,
    }
    directory = RecordRange(records=[UrlRecord(value="https://example.com")], start=0, total=1)
    account_record = AccountRecord(account=data["account"], directory=directory, receipt=data["receipt"])

    assert account_record.to_dict() == data
    deserialized = AccountRecord.from_dict(data)
    assert deserialized.account["address"] == "acc://test"


def test_chain_record():
    """Test the ChainRecord class."""
    data = {
        "name": "test-chain",
        "type": "chain-type",
        "count": 5,
        "state": [],
        "last_block_time": None,
    }
    chain_record = ChainRecord(name=data["name"], type=data["type"], count=data["count"])

    assert chain_record.to_dict() == data

    deserialized = ChainRecord.from_dict(data)
    assert deserialized.name == "test-chain"


def test_chain_entry_record():
    """Test the ChainEntryRecord class."""
    data = {
        "name": "entry1",
        "type": "entry-type",
        "count": 1,
        "state": [],
        "account": "acc://test-account",
        "index": 0,
        "entry": "entry-data",
        "receipt": {"status": "success"},
        "last_block_time": None,
    }
    chain_entry = ChainEntryRecord(
        name=data["name"],
        type=data["type"],
        count=data["count"],
        account=data["account"],
        index=data["index"],
        entry=data["entry"],
        receipt=data["receipt"],
    )

    assert chain_entry.to_dict() == data
    deserialized = ChainEntryRecord.from_dict(data)
    assert deserialized.name == "entry1"
    assert deserialized.entry == "entry-data"


def test_key_record():
    """Test the KeyRecord class."""
    data = {
        "authority": "auth://example",
        "signer": "signer-key",
        "version": 1,
        "index": 0,
        "entry": {"key": "value"},
    }
    key_record = KeyRecord(
        authority=data["authority"],
        signer=data["signer"],
        version=data["version"],
        index=data["index"],
        entry=data["entry"],
    )

    assert key_record.to_dict() == data

    deserialized = KeyRecord.from_dict(data)
    assert deserialized.authority == "auth://example"
    assert deserialized.signer == "signer-key"


def test_message_record():
    """Test the MessageRecord class."""
    data = {
        "id": "msg1",
        "message": {"type": "info"},
        "status": "delivered",
        "result": {"key": "value"},
        "received": 123456789,
        "historical": False,
    }
    message_record = MessageRecord(
        id=data["id"],
        message=data["message"],
        status=data["status"],
        result=data["result"],
        received=data["received"],
        historical=data["historical"],
    )

    # Validate the `to_dict` output matches expected serialized data
    assert message_record.to_dict() == data

    # Validate deserialization and properties
    deserialized = MessageRecord.from_dict(
        {
            "id": "msg1",
            "message": {"type": "info"},
            "status": "delivered",
            "result": {"key": "value"},
            "received": 123456789,
            "historical": False,
            "produced": None,  # Ensure these don't break deserialization
            "cause": None,
            "signatures": None,
            "last_block_time": None,
        }
    )
    assert deserialized.id == "msg1"
    assert deserialized.status == "delivered"
    assert deserialized.historical is False



def test_signature_set_record():
    """Test the SignatureSetRecord class."""
    data = {
        "account": {"name": "example-account"},
        "signatures": {
            "records": [{"id": "msg1", "message": {}, "status": None, "result": {}, "received": None}],
            "start": 0,
            "total": 1,
            "last_block_time": None,
        },
    }
    # Adjust test data to match the updated serialization logic
    expected_data = {
        "account": {"name": "example-account"},
        "signatures": {
            "records": [{"id": "msg1", "message": {}, "result": {}}],
            "start": 0,
            "total": 1,
            "last_block_time": None,
        },
    }

    signatures = RecordRange(records=[MessageRecord(id="msg1")], start=0, total=1)
    signature_set = SignatureSetRecord(account=data["account"], signatures=signatures)

    assert signature_set.to_dict() == expected_data
    deserialized = SignatureSetRecord.from_dict(data)
    assert deserialized.account["name"] == "example-account"


