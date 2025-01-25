# C:\Accumulate_Stuff\accumulate-python-client\tests\test_api\test_client.py

import pytest
from unittest.mock import AsyncMock, Mock
from accumulate.api.client import AccumulateClient
from accumulate.api.exceptions import AccumulateError
from accumulate.models.submission import Submission
from accumulate.api.querier import Query
from accumulate.models.records import Record 


@pytest.fixture
def mock_transport():
    """Fixture for mocking the RoutedTransport."""
    return AsyncMock()


@pytest.fixture
def client(mock_transport):
    """Fixture for providing an AccumulateClient instance."""
    client = AccumulateClient(base_url="http://example.com")
    client.transport = mock_transport
    return client


@pytest.fixture
def valid_query():
    """Fixture for a valid query object."""
    query = Mock(spec=Query)
    query.is_valid.return_value = True
    query.to_dict.return_value = {"key": "value"}
    return query


@pytest.fixture
def valid_envelope():
    """Fixture for a valid transaction envelope."""
    return {"transactions": [{"data": "example"}]}


def test_client_init():
    """Test AccumulateClient initialization."""
    client = AccumulateClient(base_url="http://example.com")
    assert client.transport.base_url == "http://example.com"


@pytest.mark.asyncio
async def test_query_success(client, mock_transport, valid_query):
    """Test the query method for a successful response."""
    mock_transport.send_request.return_value = {
        "record_type": "CHAIN",
        "data": {"field": "value"},
    }

    result = await client.query("test-scope", valid_query)

    assert isinstance(result, Record)
    assert result.record_type == "CHAIN"
    assert result.data == {"field": "value"}
    mock_transport.send_request.assert_awaited_once_with(
        endpoint="query/test-scope", method="GET", params={"key": "value"}
    )


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

    with pytest.raises(AccumulateError, match="Query failed: Transport error"):
        await client.query("test-scope", valid_query)


@pytest.mark.asyncio
async def test_submit_success(client, mock_transport, valid_envelope):
    """Test the submit method for a successful response."""
    # Mocking 'status' as a dictionary
    mock_transport.send_request.return_value = [{"txid": "123", "status": {"state": "PENDING"}}]

    result = await client.submit(valid_envelope, verify=True, wait=True)

    assert isinstance(result, list)
    assert all(isinstance(item, Submission) for item in result)
    assert result[0].txid == "123"
    assert result[0].status == {"state": "PENDING"}  # Adjusted check for dictionary
    mock_transport.send_request.assert_awaited_once_with(
        endpoint="submit",
        method="POST",
        data=valid_envelope,
        params={"verify": True, "wait": True},
    )


@pytest.mark.asyncio
async def test_faucet_success(client, mock_transport):
    """Test the faucet method for a successful response."""
    # Mocking 'status' as a dictionary
    mock_transport.send_request.return_value = {"txid": "123", "status": {"state": "COMPLETED"}}

    result = await client.faucet("acc://example.com")

    assert isinstance(result, Submission)
    assert result.txid == "123"
    assert result.status == {"state": "COMPLETED"}  # Adjusted check for dictionary
    mock_transport.send_request.assert_awaited_once_with(
        endpoint="faucet",
        method="POST",
        data={"account": "acc://example.com"},
        params={},
    )



@pytest.mark.asyncio
async def test_submit_exception(client, mock_transport, valid_envelope):
    """Test the submit method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="Submission failed: Transport error"):
        await client.submit(valid_envelope)


@pytest.mark.asyncio
async def test_faucet_with_token(client, mock_transport):
    """Test the faucet method with a token URL."""
    # Mocking 'status' as a dictionary
    mock_transport.send_request.return_value = {"txid": "123", "status": {"state": "COMPLETED"}}

    # Use the same account value here as in the mock expectation
    result = await client.faucet("acc://adi.acme", token_url="acc://adi.acme/token")

    assert result.txid == "123"
    assert result.status == {"state": "COMPLETED"}  # Adjusted check for dictionary
    mock_transport.send_request.assert_awaited_once_with(
        endpoint="faucet",
        method="POST",
        data={"account": "acc://adi.acme"},
        params={"token": "acc://adi.acme/token"},
    )


@pytest.mark.asyncio
async def test_faucet_missing_account(client):
    """Test the faucet method with a missing account."""
    with pytest.raises(ValueError, match="Account URL must be provided."):
        await client.faucet("")


@pytest.mark.asyncio
async def test_faucet_exception(client, mock_transport):
    """Test the faucet method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="Faucet request failed: Transport error"):
        await client.faucet("acc://example.com")


@pytest.mark.asyncio
async def test_validate_success(client, mock_transport, valid_envelope):
    """Test the validate method for a successful response."""
    mock_transport.send_request.return_value = {"valid": True, "details": "Valid"}

    result = await client.validate(valid_envelope, full=True)

    assert result == {"valid": True, "details": "Valid"}
    mock_transport.send_request.assert_awaited_once_with(
        endpoint="validate",
        method="POST",
        data=valid_envelope,
        params={"full": True},
    )


@pytest.mark.asyncio
async def test_validate_exception(client, mock_transport, valid_envelope):
    """Test the validate method when an exception occurs."""
    mock_transport.send_request.side_effect = Exception("Transport error")

    with pytest.raises(AccumulateError, match="Validation failed: Transport error"):
        await client.validate(valid_envelope)
