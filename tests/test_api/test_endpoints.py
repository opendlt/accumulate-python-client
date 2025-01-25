# C:\Accumulate_Stuff\accumulate-python-client\tests\test_api\test_endpoints.py  

import pytest
from unittest.mock import AsyncMock, MagicMock
from accumulate.api.endpoints import EndpointsService
from accumulate.api.exceptions import AccumulateError
from accumulate.models.node_info import NodeInfo
from accumulate.models.service import FindServiceOptions, FindServiceResult, ServiceAddress


@pytest.fixture
def endpoints_service():
    """Fixture to create an EndpointsService with a mock transport."""
    mock_transport = MagicMock()
    return EndpointsService(mock_transport), mock_transport



@pytest.mark.asyncio
async def test_register_service(endpoints_service):
    service, _ = endpoints_service
    service_address = "acc://test-service"
    handler = "test-handler"

    service.register_service(service_address, handler)
    assert service.services[service_address] == handler

    with pytest.raises(AccumulateError, match="already registered"):
        service.register_service(service_address, handler)


@pytest.mark.asyncio
async def test_get_node_info(endpoints_service):
    service, mock_transport = endpoints_service
    # Updated mock response to match NodeInfo fields
    mock_response = {
        "peer_id": "1234",
        "network": "testnet",
        "services": [{"type": 1, "argument": "test-arg"}],
        "version": "1.0.0",
        "commit": "abc123"
    }
    mock_transport.send_request = AsyncMock(return_value=mock_response)

    result = await service.get_node_info()
    assert isinstance(result, NodeInfo)
    assert result.peer_id == "1234"
    assert result.network == "testnet"
    assert result.version == "1.0.0"
    assert result.commit == "abc123"


@pytest.mark.asyncio
async def test_get_node_info_failure(endpoints_service):
    service, mock_transport = endpoints_service
    mock_transport.send_request = AsyncMock(side_effect=Exception("Connection error"))

    with pytest.raises(AccumulateError, match="Failed to fetch node info"):
        await service.get_node_info()


@pytest.mark.asyncio
async def test_find_service(endpoints_service):
    service, mock_transport = endpoints_service
    options = FindServiceOptions(network="acc://test-service")
    # Updated mock response to match FindServiceResult fields
    mock_response = [
        {
            "peer_id": "peer-1",
            "status": "online",
            "addresses": ["acc://service-address"]
        }
    ]
    mock_transport.send_request = AsyncMock(return_value=mock_response)

    result = await service.find_service(options)
    assert isinstance(result, list)
    assert isinstance(result[0], FindServiceResult)
    assert result[0].peer_id == "peer-1"
    assert result[0].status == "online"
    assert result[0].addresses == ["acc://service-address"]


@pytest.mark.asyncio
async def test_find_service_failure(endpoints_service):
    service, mock_transport = endpoints_service
    options = FindServiceOptions(network="acc://test-service")
    mock_transport.send_request = AsyncMock(side_effect=Exception("Service not found"))

    with pytest.raises(AccumulateError, match="Service search failed"):
        await service.find_service(options)


@pytest.mark.asyncio
async def test_query_account(endpoints_service):
    service, mock_transport = endpoints_service
    account_url = "acc://test-account"
    mock_response = {"result": {"type": "account", "balance": 1000}}
    mock_transport.send_request = AsyncMock(return_value=mock_response)

    result = await service.query_account(account_url, include_receipt=True)
    assert result["type"] == "account"
    assert result["balance"] == 1000


@pytest.mark.asyncio
async def test_query_account_failure(endpoints_service):
    service, mock_transport = endpoints_service
    account_url = "acc://test-account"
    mock_transport.send_request = AsyncMock(side_effect=Exception("Query failed"))

    with pytest.raises(AccumulateError, match="Failed to query account"):
        await service.query_account(account_url)


@pytest.mark.asyncio
async def test_execute_direct(endpoints_service):
    service, mock_transport = endpoints_service
    payload = {"transaction": "test-payload"}
    mock_response = {"result": {"status": "success"}}
    mock_transport.send_request = AsyncMock(return_value=mock_response)

    result = await service.execute_direct(payload)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_execute_direct_failure(endpoints_service):
    service, mock_transport = endpoints_service
    payload = {"transaction": "test-payload"}
    mock_transport.send_request = AsyncMock(side_effect=Exception("Execution failed"))

    with pytest.raises(AccumulateError, match="Failed to execute direct transaction"):
        await service.execute_direct(payload)


@pytest.mark.asyncio
async def test_get_transaction(endpoints_service):
    service, mock_transport = endpoints_service
    txid = "test-txid"
    mock_response = {"result": {"txid": txid, "status": "confirmed"}}
    mock_transport.send_request = AsyncMock(return_value=mock_response)

    result = await service.get_transaction(txid)
    assert result["txid"] == txid
    assert result["status"] == "confirmed"


@pytest.mark.asyncio
async def test_get_transaction_failure(endpoints_service):
    service, mock_transport = endpoints_service
    txid = "test-txid"
    mock_transport.send_request = AsyncMock(side_effect=Exception("Transaction not found"))

    with pytest.raises(AccumulateError, match="Failed to fetch transaction details"):
        await service.get_transaction(txid)


@pytest.mark.asyncio
async def test_faucet(endpoints_service):
    service, mock_transport = endpoints_service
    account_url = "acc://test-account"
    mock_response = {"result": {"status": "tokens sent"}}
    mock_transport.send_request = AsyncMock(return_value=mock_response)

    result = await service.faucet(account_url)
    assert result["status"] == "tokens sent"


@pytest.mark.asyncio
async def test_faucet_failure(endpoints_service):
    service, mock_transport = endpoints_service
    account_url = "acc://test-account"
    mock_transport.send_request = AsyncMock(side_effect=Exception("Faucet error"))

    with pytest.raises(AccumulateError, match="Failed to request tokens from faucet"):
        await service.faucet(account_url)


@pytest.mark.asyncio
async def test_query_minor_blocks(endpoints_service):
    service, mock_transport = endpoints_service
    url = "acc://test-block"
    count = 2
    mock_response = {"result": {"blocks": [{"height": 1}, {"height": 2}]}}
    mock_transport.send_request = AsyncMock(return_value=mock_response)

    result = await service.query_minor_blocks(url, count)
    assert len(result["blocks"]) == 2
    assert result["blocks"][0]["height"] == 1


@pytest.mark.asyncio
async def test_query_minor_blocks_failure(endpoints_service):
    service, mock_transport = endpoints_service
    url = "acc://test-block"
    count = 2
    mock_transport.send_request = AsyncMock(side_effect=Exception("Block query failed"))

    with pytest.raises(AccumulateError, match="Failed to query minor blocks"):
        await service.query_minor_blocks(url, count)
