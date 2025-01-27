# accumulate-python-client\tests\test_api\test_transport.py

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from accumulate.api.transport import RoutedTransport


@pytest.fixture
def transport():
    """Fixture for initializing the RoutedTransport instance."""
    return RoutedTransport(base_url="http://example.com")


@pytest.mark.asyncio
async def test_send_request_get_success(transport):
    """Test a successful GET request."""
    async_mock_response = httpx.Response(
        status_code=200,
        request=httpx.Request("GET", url="http://example.com/test"),
        json={"key": "value"},
    )

    with patch.object(transport.client, "request", AsyncMock(return_value=async_mock_response)) as mock_request:
        response = await transport.send_request(endpoint="/test", method="GET")
        assert response == {"key": "value"}
        mock_request.assert_awaited_once_with(
            method="GET",
            url="/test",
            params=None,
            json=None,
        )


@pytest.mark.asyncio
async def test_send_request_post_success(transport):
    """Test a successful POST request with data."""
    async_mock_response = httpx.Response(
        status_code=200,
        request=httpx.Request("POST", url="http://example.com/submit"),
        json={"success": True},
    )

    with patch.object(transport.client, "request", AsyncMock(return_value=async_mock_response)) as mock_request:
        response = await transport.send_request(
            endpoint="/submit",
            method="POST",
            data={"transaction": "example"},
        )
        assert response == {"success": True}
        mock_request.assert_awaited_once_with(
            method="POST",
            url="/submit",
            params=None,
            json={"transaction": "example"},
        )


@pytest.mark.asyncio
async def test_send_request_with_params(transport):
    """Test a request with query parameters."""
    async_mock_response = httpx.Response(
        status_code=200,
        request=httpx.Request("GET", url="http://example.com/query"),
        json={"result": "ok"},
    )

    with patch.object(transport.client, "request", AsyncMock(return_value=async_mock_response)) as mock_request:
        response = await transport.send_request(
            endpoint="/query",
            method="GET",
            params={"scope": "test"},
        )
        assert response == {"result": "ok"}
        mock_request.assert_awaited_once_with(
            method="GET",
            url="/query",
            params={"scope": "test"},
            json=None,
        )


@pytest.mark.asyncio
async def test_send_request_request_error(transport):
    """Test handling of a request error."""
    with patch.object(transport.client, "request", AsyncMock(side_effect=httpx.RequestError("Request failed"))):
        with pytest.raises(Exception, match="Request failed: Request failed"):
            await transport.send_request(endpoint="/error", method="GET")


@pytest.mark.asyncio
async def test_send_request_http_status_error(transport):
    """Test handling of an HTTP status error."""
    async_mock_response = httpx.Response(
        status_code=404,
        request=httpx.Request("GET", url="http://example.com/not-found"),
        text="Not Found",
    )

    with patch.object(transport.client, "request", AsyncMock(side_effect=httpx.HTTPStatusError(
            message="Not Found",
            request=None,
            response=async_mock_response))):
        with pytest.raises(Exception, match="HTTP error: 404 - Not Found"):
            await transport.send_request(endpoint="/not-found", method="GET")


@pytest.mark.asyncio
async def test_send_request_invalid_json_response(transport):
    """Test handling of an invalid JSON response."""
    async_mock_response = httpx.Response(
        status_code=200,
        request=httpx.Request("GET", url="http://example.com/bad-json"),
        content=b"Invalid JSON",
    )

    with patch.object(transport.client, "request", AsyncMock(return_value=async_mock_response)):
        with pytest.raises(Exception, match="Invalid JSON response"):
            await transport.send_request(endpoint="/bad-json", method="GET")


@pytest.mark.asyncio
async def test_close_transport(transport):
    """Test closing the transport client."""
    with patch.object(transport.client, "aclose", new_callable=AsyncMock) as mock_close:
        await transport.close()
        mock_close.assert_awaited_once()
