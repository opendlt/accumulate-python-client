# accumulate-python-client\tests\test_api\test_querier.py

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from accumulate.api.querier import Querier
from accumulate.api.exceptions import AccumulateError
from accumulate.models.records import (
    Record,
    AccountRecord,
    MessageRecord,
    ChainRecord,
    RecordRange,
    ChainEntryRecord,
)
from accumulate.models.events import BlockEvent
from accumulate.models.queries import Query
from accumulate.utils.url import URL
from accumulate.api.context import RequestContext
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@pytest.fixture
def querier_service():
    """Fixture to create a Querier instance with a mock transport."""
    mock_transport = MagicMock()
    return Querier(mock_transport), mock_transport


class MockQuery:
    """Mock Query object with a valid query_type and parameters."""
    def __init__(self, query_type_name="TestQuery"):
        self.query_type = MagicMock(name=query_type_name)
        self.query_type.name = query_type_name

    def is_valid(self):
        return True

    def to_dict(self):
        return {"key": "value"}


# --- Test cases for generic queries ---
@pytest.mark.asyncio
async def test_query_success(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("TestQuery")
    mock_response = Record(record_type="test", data={"key": "value"})
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query(RequestContext(), "test-scope", mock_query, Record)
    assert isinstance(result, Record)
    assert result.record_type == "test"
    assert result.data["key"] == "value"


@pytest.mark.asyncio
async def test_query_invalid_query(querier_service):
    querier, _ = querier_service
    mock_query = MockQuery("TestQuery")
    mock_query.is_valid = lambda: False

    with pytest.raises(ValueError, match="Invalid query."):
        await querier.query(RequestContext(), "test-scope", mock_query, Record)

@pytest.mark.asyncio
async def test_query_transport_error(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("TestQuery")
    mock_transport.send_message = AsyncMock(side_effect=Exception("Transport error"))

    with pytest.raises(AccumulateError, match="Query failed: .*Transport error.*"):
        await querier.query(RequestContext(), "test-scope", mock_query, Record)


# --- Test cases for record queries ---
@pytest.mark.asyncio
async def test_query_record_success(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("TestQuery")
    mock_response = AccountRecord(
        record_type="account",
        account={"address": "acc://test"},
        directory=RecordRange(records=[], start=0, total=0),
    )
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query_record(RequestContext(), URL("acc://test"), mock_query, AccountRecord)
    assert isinstance(result, AccountRecord)
    assert result.account["address"] == "acc://test"


@pytest.mark.asyncio
async def test_query_record_wrong_type(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("TestQuery")
    mock_response = MessageRecord(
        record_type="message",
        id="msg1",
        status="unknown"
    )
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    with pytest.raises(AccumulateError, match="Deserialization failed: Expected .*AccountRecord.*, got .*MessageRecord.*"):
        await querier.query_record(RequestContext(), URL("acc://test"), mock_query, AccountRecord)


# --- Test cases for event queries ---
@pytest.mark.asyncio
async def test_query_events_success(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("EventQuery")
    mock_response = RecordRange(
        records=[
            BlockEvent(
                partition="test-partition",
                index=123,
                time=datetime.now(timezone.utc),  # Use timezone.utc for a UTC-aware datetime
                major=1,
                entries=[{"entry": "test"}]
            )
        ],
        start=0,
        total=1,
        item_type=BlockEvent  # Specify the correct item type
    )
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query_events(RequestContext(), URL("acc://test"), mock_query)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], BlockEvent)
    assert result[0].partition == "test-partition"
    assert result[0].index == 123
    assert result[0].major == 1
    assert result[0].entries == [{"entry": "test"}]



@pytest.mark.asyncio
async def test_query_events_unknown_type(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("EventQuery")
    mock_response = RecordRange(records=[
        Record(record_type="UnknownEvent", data={"key": "value"}),  # Unknown event
        BlockEvent(
            partition="test-partition",
            index=123,
            time=datetime.now(timezone.utc),
            major=1,
            entries=[{"entry": "test"}],
        ),  # Known event
    ])
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query_events(RequestContext(), URL("acc://test"), mock_query)

    # Validate that the known event is processed and the unknown is skipped
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], BlockEvent)
    assert result[0].partition == "test-partition"
    assert result[0].index == 123
    assert result[0].major == 1
    assert result[0].entries == [{"entry": "test"}]



# --- Test cases for chain queries ---
@pytest.mark.asyncio
async def test_query_chain_success(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("ChainQuery")
    mock_response = ChainRecord(
        record_type="chain",
        name="test-chain",
        count=5,
        state=[],
    )
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query_chain(RequestContext(), URL("acc://test"), mock_query)
    assert isinstance(result, ChainRecord)
    assert result.name == "test-chain"


@pytest.mark.asyncio
async def test_query_chain_entries_success(querier_service):
    querier, mock_transport = querier_service
    mock_query = MockQuery("ChainQuery")
    mock_response = RecordRange(
        records=[ChainEntryRecord(name="entry1")],
        start=0,
        total=1,
    )
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query_chain_entries(RequestContext(), URL("acc://test"), mock_query)
    assert isinstance(result, RecordRange)
    assert len(result.records) == 1
    assert isinstance(result.records[0], ChainEntryRecord)
    assert result.records[0].name == "entry1"

@pytest.mark.asyncio
async def test_query_events_invalid_record_type(querier_service):
    """Test query_events with an invalid record type."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("EventQuery")
    mock_response = RecordRange(
        records=[{"unexpected": "data"}],  # Invalid record
        start=0,
        total=1,
    )
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    with pytest.raises(AccumulateError, match="Deserialization failed: .*Expected <class 'accumulate.models.records.Record'>.*got .*<class 'dict'>.*"):
        await querier.query_events(RequestContext(), URL("acc://test"), mock_query)

@pytest.mark.asyncio
async def test_query_events_unknown_event_type(querier_service, caplog):
    """Test query_events with an unknown event type."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("EventQuery")
    mock_response = RecordRange(
        records=[Record(record_type="UnknownEvent", data={"key": "value"})],  # Unknown event type
        start=0,
        total=1,
    )
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    with caplog.at_level(logging.WARNING):
        result = await querier.query_events(RequestContext(), URL("acc://test"), mock_query)

    assert len(result) == 0  # Unknown events should be skipped
    assert "Skipping unknown event type: UnknownEvent" in caplog.text


@pytest.mark.asyncio
async def test_query_events_exception(querier_service):
    """Test query_events with an exception raised during processing."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("EventQuery")
    mock_transport.send_message = AsyncMock(side_effect=Exception("Unexpected error"))

    with pytest.raises(AccumulateError, match="Error in query_events: .*Unexpected error.*"):
        await querier.query_events(RequestContext(), URL("acc://test"), mock_query)



def test_deserialize_response_invalid_data(querier_service):
    """Test _deserialize_response with invalid data."""
    querier, _ = querier_service
    with pytest.raises(AccumulateError, match="Expected .*RecordRange.*, got .*dict.*"):
        querier._deserialize_response({"unexpected": "data"}, RecordRange)


def test_deserialize_response_wrong_recordrange_type(querier_service):
    """Test _deserialize_response with invalid RecordRange item type."""
    querier, _ = querier_service
    invalid_record_range = RecordRange(records=["invalid"], start=0, total=1)
    
    with pytest.raises(AccumulateError, match="Deserialization failed: .*Expected <class 'accumulate.models.records.Record'>.*got .*<class 'str'>.*"):
        querier._deserialize_response(invalid_record_range, RecordRange)


def test_deserialize_response_exception(querier_service):
    """Test _deserialize_response with an exception."""
    querier, _ = querier_service
    with pytest.raises(AccumulateError, match="Deserialization failed: .*"):
        querier._deserialize_response(None, Record)


@pytest.mark.asyncio
async def test_query_generic_no_response(querier_service):
    """Test query_generic without a proper response."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("GenericQuery")
    mock_transport.send_message = AsyncMock(return_value=None)  # No response

    with pytest.raises(AccumulateError, match="Deserialization failed: .*"):
        await querier.query_generic(RequestContext(), URL("acc://test"), mock_query, Record)

@pytest.mark.asyncio
async def test_query_account_unexpected_type(querier_service):
    """Test query_account with an unexpected type."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("AccountQuery")
    mock_transport.send_message = AsyncMock(return_value=MessageRecord())

    with pytest.raises(AccumulateError, match="Deserialization failed: Expected .*AccountRecord.*, got .*MessageRecord.*"):
        await querier.query_account(RequestContext(), URL("acc://test"), mock_query)


@pytest.mark.asyncio
async def test_query_chain_entries_invalid_nested_type(querier_service):
    """Test query_chain_entries with invalid nested types."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("ChainEntriesQuery")
    mock_response = RecordRange(records=["invalid_record"], start=0, total=1)
    mock_transport.send_message = AsyncMock(return_value=mock_response)

    with pytest.raises(AccumulateError, match="Deserialization failed: .*RecordRange contains items of an incorrect type.*"):
        await querier.query_chain_entries(RequestContext(), URL("acc://test"), mock_query)


class MockQuery(Query):
    def __init__(self, query_type_name):
        self.query_type = MagicMock(name="QueryType")
        self.query_type.name = query_type_name

    def is_valid(self):
        return True

    def to_dict(self):
        return {"key": "value"}

@pytest.mark.asyncio
async def test_query_transaction_success(querier_service):
    """Test query_transaction with a valid MessageRecord."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("TransactionQuery")
    txid = URL("acc://transaction-id")
    mock_response = MessageRecord()

    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query_transaction(RequestContext(), txid, mock_query)
    assert isinstance(result, MessageRecord)
    assert result == mock_response


@pytest.mark.asyncio
async def test_query_transaction_invalid_response(querier_service):
    """Test query_transaction with an invalid response type."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("TransactionQuery")
    txid = URL("acc://transaction-id")
    mock_response = "InvalidResponse"  # Not a MessageRecord

    mock_transport.send_message = AsyncMock(return_value=mock_response)

    # Updated match pattern to align with the full error message
    with pytest.raises(AccumulateError, match="Deserialization failed: Expected <class 'accumulate.models.records.MessageRecord'>, got <class 'str'>"):
        await querier.query_transaction(RequestContext(), txid, mock_query)


@pytest.mark.asyncio
async def test_query_transaction_transport_error(querier_service):
    """Test query_transaction with a transport exception."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("TransactionQuery")
    txid = URL("acc://transaction-id")

    mock_transport.send_message = AsyncMock(side_effect=Exception("Transport error"))

    with pytest.raises(AccumulateError, match="Query failed: .*Transport error.*"):
        await querier.query_transaction(RequestContext(), txid, mock_query)
@pytest.mark.asyncio
async def test_query_block_success(querier_service):
    """Test query_block with a valid RecordRange."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("BlockQuery")
    scope = URL("acc://block-scope")
    mock_response = RecordRange()

    mock_transport.send_message = AsyncMock(return_value=mock_response)

    result = await querier.query_block(RequestContext(), scope, mock_query)
    assert isinstance(result, RecordRange)
    assert result == mock_response

@pytest.mark.asyncio
async def test_query_block_invalid_response(querier_service):
    """Test query_block with an invalid response type."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("BlockQuery")
    scope = URL("acc://block-scope")
    mock_response = "InvalidResponse"  # Not a RecordRange

    mock_transport.send_message = AsyncMock(return_value=mock_response)

    # Updated match to align with the actual error message
    with pytest.raises(AccumulateError, match="Deserialization failed: Expected RecordRange, got <class 'str'>"):
        await querier.query_block(RequestContext(), scope, mock_query)



@pytest.mark.asyncio
async def test_query_block_transport_error(querier_service):
    """Test query_block with a transport exception."""
    querier, mock_transport = querier_service
    mock_query = MockQuery("BlockQuery")
    scope = URL("acc://block-scope")

    mock_transport.send_message = AsyncMock(side_effect=Exception("Transport error"))

    with pytest.raises(AccumulateError, match="Query failed: .*Transport error.*"):
        await querier.query_block(RequestContext(), scope, mock_query)
