# C:\Accumulate_Stuff\accumulate-python-client\tests\test_api\test_querier.py

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

    with pytest.raises(AccumulateError, match="Query failed: Transport error"):
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
