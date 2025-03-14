# accumulate-python-client\tests\test_api\test_client.py

import pytest
from unittest.mock import AsyncMock, Mock
from accumulate.api.client import AccumulateClient
from accumulate.api.exceptions import AccumulateError
from accumulate.models.submission import Submission
from accumulate.models.records import Record
from accumulate.models.queries import Query
from accumulate.models.service import FindServiceOptions, FindServiceResult

@pytest.fixture
def mock_transport():
    """Fixture for mocking the RoutedTransport."""
    return AsyncMock()

@pytest.fixture
def client(mock_transport):
    """Fixture for providing an AccumulateClient instance."""
    client = AccumulateClient(base_url="https://mock.accumulatenetwork.io/V#")
    client.transport = mock_transport
    return client

@pytest.fixture
def valid_query():
    """Fixture for a valid query object."""
    query = Mock(spec=Query)
    query.is_valid.return_value = True
    query.to_dict.return_value = {"key": "value"}
    # Provide a dummy query_type with a to_rpc_format() method.
    query.query_type = Mock()
    query.query_type.to_rpc_format.return_value = "dummy_query_type"
    return query

@pytest.fixture
def valid_envelope():
    """Fixture for a valid transaction envelope."""
    return {
        "signatures": [{"signature": "dummy_signature"}],
        "transaction": [
            {
                "header": {"dummy_header": "value"},
                "body": {"dummy_body": "value"}
            }
        ]
    }

# Added fixture for find_service_options
@pytest.fixture
def find_service_options():
    """Fixture for FindServiceOptions."""
    options = Mock(spec=FindServiceOptions)
    options.to_dict.return_value = {"dummy": "option"}  # Dummy options for testing
    return options

def test_client_init():
    """Test AccumulateClient initialization."""
    client = AccumulateClient(base_url="http://example.com")
    assert client.transport.base_url == "http://example.com"

@pytest.mark.asyncio
async def test_query_success(client, mock_transport, valid_query):
    """Test the query method for a successful response using JSON-RPC."""
    mock_transport.send_request.return_value = {"result": {"record_type": "CHAIN", "data": {"field": "value"}}}

    result = await client.query("test-scope", valid_query)

    assert isinstance(result, Record)
    assert result.record_type == "CHAIN"
    assert result.data == {"field": "value"}
    mock_transport.send_request.assert_awaited_once()

@pytest.mark.asyncio
async def test_query_invalid_query(client, valid_query):
    """Test the query method with an invalid query."""
    valid_query.is_valid.return_value = False

    with pytest.raises(ValueError, match="Invalid query."):
        await client.query("test-scope", valid_query)

@pytest.mark.asyncio
async def test_query_exception(client, mock_transport, valid_query):
    """Test the query method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="JSON-RPC request failed \\(query\\): Transport error"):
        await client.query("test-scope", valid_query)

@pytest.mark.asyncio
async def test_submit_success(client, mock_transport, valid_envelope):
    """Test the submit method for a successful response."""
    # The mocked transport returns a list of transaction details (as dicts).
    mock_transport.send_request.return_value = {"result": [{"txid": "123", "status": {"state": "PENDING"}}]}

    result = await client.submit(valid_envelope, verify=True, wait=True)

    assert isinstance(result, list)
    # Since the implementation returns raw dictionaries, verify keys and values
    assert all(isinstance(item, dict) for item in result)
    assert result[0]["txid"] == "123"
    assert result[0]["status"] == {"state": "PENDING"}
    mock_transport.send_request.assert_awaited_once()

@pytest.mark.asyncio
async def test_submit_exception(client, mock_transport, valid_envelope):
    """Test the submit method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="JSON-RPC request failed \\(submit\\): Transport error"):
        await client.submit(valid_envelope)

@pytest.mark.asyncio
async def test_faucet_success(client, mock_transport):
    """Test the faucet method for a successful response."""
    mock_transport.send_request.return_value = {"result": {"txid": "123", "status": {"state": "COMPLETED"}}}

    result = await client.faucet("acc://example.com")

    assert isinstance(result, Submission)
    assert result.txid == "123"
    assert result.status == {"state": "COMPLETED"}
    mock_transport.send_request.assert_awaited_once()

@pytest.mark.asyncio
async def test_faucet_exception(client, mock_transport):
    """Test the faucet method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="JSON-RPC request failed \\(faucet\\): Transport error"):
        await client.faucet("acc://example.com")

@pytest.mark.asyncio
async def test_validate_success(client, mock_transport, valid_envelope):
    """Test the validate method for a successful response."""
    mock_transport.send_request.return_value = {"result": {"valid": True, "details": "Valid"}}

    result = await client.validate(valid_envelope, full=True)

    assert result == {"valid": True, "details": "Valid"}
    mock_transport.send_request.assert_awaited_once()

@pytest.mark.asyncio
async def test_validate_exception(client, mock_transport, valid_envelope):
    """Test the validate method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="JSON-RPC request failed \\(validate\\): Transport error"):
        await client.validate(valid_envelope)

@pytest.mark.asyncio
async def test_find_service_success(client, mock_transport, find_service_options):
    """Test the find_service method for a successful response."""
    mock_transport.send_request.return_value = {
        "result": [
            {
                "peer_id": "test-peer-id",
                "status": "available",
                "addresses": ["addr1", "addr2"]
            }
        ]
    }

    result = await client.find_service(find_service_options)

    assert isinstance(result, list)
    assert isinstance(result[0], FindServiceResult)
    assert result[0].peer_id == "test-peer-id"
    assert result[0].status == "available"
    assert result[0].addresses == ["addr1", "addr2"]

    mock_transport.send_request.assert_awaited_once()

@pytest.mark.asyncio
async def test_find_service_exception(client, mock_transport, find_service_options):
    """Test the find_service method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="JSON-RPC request failed \\(find-service\\): Transport error"):
        await client.find_service(find_service_options)

@pytest.mark.asyncio
async def test_metrics_success(client, mock_transport):
    """Test the metrics method for a successful response."""
    mock_transport.send_request.return_value = {"result": {"tps": 100, "blockTime": 5}}

    result = await client.metrics()

    assert result == {"tps": 100, "blockTime": 5}
    mock_transport.send_request.assert_awaited_once()

@pytest.mark.asyncio
async def test_list_snapshots_success(client, mock_transport):
    """Test the list_snapshots method for a successful response."""
    mock_transport.send_request.return_value = {"result": [{"id": "snapshot1"}]}

    result = await client.list_snapshots()

    assert isinstance(result, list)
    assert result == [{"id": "snapshot1"}]
    mock_transport.send_request.assert_awaited_once()
