 # accumulate-python-client\accumulate\api\endpoints.py


from typing import Dict, List, Any
from accumulate.api.exceptions import AccumulateError
from accumulate.models.node_info import NodeInfo
from accumulate.api.transport import RoutedTransport
from accumulate.models.service import ServiceAddress, FindServiceOptions, FindServiceResult

class EndpointsService:
    """Defines API endpoints for Accumulate network interactions."""

    def __init__(self, transport: RoutedTransport):
        self.transport = transport
        self.services: Dict[str, str] = {}

    def register_service(self, service_address: ServiceAddress, handler: str):
        """Register a service handler for a given service address."""
        key = str(service_address)
        if key in self.services:
            raise AccumulateError(f"Service {key} is already registered.")
        self.services[key] = handler

    async def get_node_info(self) -> NodeInfo:
        """Retrieve node information."""
        try:
            response = await self.transport.send_request(
                endpoint="node-info", method="GET"
            )
            return NodeInfo(**response)
        except Exception as e:
            raise AccumulateError(f"Failed to fetch node info: {e}")

    async def find_service(self, options: FindServiceOptions) -> List[FindServiceResult]:
        """Find services on the network."""
        try:
            response = await self.transport.send_request(
                endpoint="find-service",
                method="POST",
                data=options.to_dict(),
            )
            return [FindServiceResult(**res) for res in response]
        except Exception as e:
            raise AccumulateError(f"Service search failed: {e}")

    async def query_account(self, account_url: str, include_receipt: bool = False) -> Dict[str, Any]:
        """
        Query the state of an account.
        
        :param account_url: The URL of the account to query.
        :param include_receipt: Whether to include the receipt in the response.
        :return: The account state and additional information.
        """
        try:
            params = {
                "scope": account_url,
                "query": {
                    "queryType": "default",
                    "includeReceipt": include_receipt
                }
            }
            response = await self.transport.send_request(
                endpoint="query",
                method="POST",
                data=params,
            )
            return response.get("result", {})
        except Exception as e:
            raise AccumulateError(f"Failed to query account: {e}")

    async def execute_direct(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a direct transaction."""
        try:
            response = await self.transport.send_request(
                endpoint="execute-direct",
                method="POST",
                data=payload,
            )
            return response.get("result", {})
        except Exception as e:
            raise AccumulateError(f"Failed to execute direct transaction: {e}")

    async def get_transaction(self, txid: str) -> Dict[str, Any]:
        """Get details of a transaction."""
        try:
            response = await self.transport.send_request(
                endpoint="query-tx",
                method="POST",
                data={"txid": txid},
            )
            return response.get("result", {})
        except Exception as e:
            raise AccumulateError(f"Failed to fetch transaction details: {e}")

    async def faucet(self, account_url: str) -> Dict[str, Any]:
        """Request tokens from the testnet faucet."""
        try:
            response = await self.transport.send_request(
                endpoint="faucet",
                method="POST",
                data={"url": account_url},
            )
            return response.get("result", {})
        except Exception as e:
            raise AccumulateError(f"Failed to request tokens from faucet: {e}")

    async def query_minor_blocks(self, url: str, count: int) -> Dict[str, Any]:
        """Query minor blocks for a given URL."""
        try:
            response = await self.transport.send_request(
                endpoint="query-minor-blocks",
                method="POST",
                data={"url": url, "count": count},
            )
            return response.get("result", {})
        except Exception as e:
            raise AccumulateError(f"Failed to query minor blocks: {e}")
