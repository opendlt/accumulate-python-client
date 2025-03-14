# accumulate-python-client\accumulate\api\transport.py

import logging
import httpx
from typing import Any, Dict

# Initialize logging (set to INFO to suppress excessive DEBUG messages)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RoutedTransport")


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
        self, endpoint: str, method: str = "GET", params: Dict[str, Any] = None, data: Dict[str, Any] = None, debug: bool = False
    ) -> Dict[str, Any]:
        """
        Print the exact JSON-RPC request without sending it if debug mode is enabled.

        Args:
            endpoint (str): The API endpoint (e.g., "query/{scope}").
            method (str): The HTTP method (e.g., "GET", "POST").
            params (Dict[str, Any], optional): Query parameters for the request.
            data (Dict[str, Any], optional): JSON body for the request.
            debug (bool): If True, print the JSON request instead of sending it.

        Returns:
            Dict[str, Any]: The printed request data as a dictionary.

        Raises:
            Exception: If the request fails or the response contains an error.
        """

        # Construct the exact JSON-RPC request
        rpc_request = {
            "method": method,
            "url": f"{self.base_url}/{endpoint}",
            "params": params,
            "json": data
        }

        # If debug mode is enabled, print the JSON and return without sending
        if debug:
            formatted_json = json.dumps(rpc_request, indent=4)  # Pretty-print JSON
            logger.info(f" RPC Request (Not Sent):\n{formatted_json}")
            return rpc_request  # Return the request object instead of sending

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
            logger.error(f" Request failed: {e}")
            raise Exception(f"Request failed: {e}")

        except httpx.HTTPStatusError as e:
            logger.error(f" HTTP error {e.response.status_code}: {e.response.text}")
            raise Exception(f"HTTP error: {e.response.status_code} - {e.response.text}")

        except ValueError as e:
            logger.error(f" Invalid JSON response: {e}")
            raise Exception(f"Invalid JSON response: {e}")

    async def close(self):
        """Close the transport client."""
        await self.client.aclose()
