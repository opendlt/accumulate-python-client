# C:\Accumulate_Stuff\accumulate-python-client\accumulate\api\transport.py

import httpx
from typing import Any, Dict


class RoutedTransport:
    """Handles HTTP transport for the Accumulate RPC API."""

    def __init__(self, base_url: str, timeout: int = 15):
        """
        Initialize the transport layer.

        Args:
            base_url (str): The base URL of the Accumulate network (e.g., mainnet or testnet).
            timeout (int): Request timeout in seconds.
        """
        self.base_url = base_url
        self.client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def send_request(
        self, endpoint: str, method: str = "GET", params: Dict[str, Any] = None, data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Send an HTTP request to the RPC API.

        Args:
            endpoint (str): The API endpoint (e.g., "query/{scope}").
            method (str): The HTTP method (e.g., "GET", "POST").
            params (Dict[str, Any], optional): Query parameters for the request.
            data (Dict[str, Any], optional): JSON body for the request.

        Returns:
            Dict[str, Any]: Parsed JSON response from the API.

        Raises:
            Exception: If the request fails or the response contains an error.
        """
        try:
            response = await self.client.request(
                method=method,
                url=endpoint,
                params=params,
                json=data,
            )
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            raise Exception(f"Request failed: {e}")
        except httpx.HTTPStatusError as e:
            raise Exception(f"HTTP error: {e.response.status_code} - {e.response.text}")
        except ValueError as e:
            raise Exception(f"Invalid JSON response: {e}")

    async def close(self):
        """Close the transport client."""
        await self.client.aclose()
