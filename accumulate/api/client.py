# C:\Accumulate_Stuff\accumulate-python-client\accumulate\api\client.py 

from typing import Any, Dict, List, Optional
from accumulate.api.transport import RoutedTransport
from accumulate.api.exceptions import AccumulateError
from accumulate.models.submission import Submission
from accumulate.models.service import ServiceAddress, FindServiceOptions, FindServiceResult
from accumulate.models.records import Record 
from accumulate.models.queries import Query 


class AccumulateClient:
    """Client for interacting with the Accumulate RPC API."""

    def __init__(self, base_url: str):
        """
        Initialize the client with the base URL for the RPC API.

        Args:
            base_url (str): The base URL of the Accumulate network (e.g., mainnet or testnet).
        """
        self.transport = RoutedTransport(base_url)

    async def query(self, scope: str, query: Query) -> Record:
        """Submit a query to the Accumulate network."""
        if not query.is_valid():
            raise ValueError("Invalid query.")
        try:
            response = await self.transport.send_request(
                endpoint=f"query/{scope}",
                method="GET",
                params=query.to_dict(),
            )
            return Record(
                record_type=response.get("record_type", "UNKNOWN"),
                data=response.get("data", {}),
            )
        except Exception as e:
            raise AccumulateError(f"Query failed: {e}")

    async def submit(
        self, envelope: Dict[str, Any], verify: bool = False, wait: bool = False
    ) -> List[Submission]:
        """Submit a transaction to the Accumulate network."""
        try:
            response = await self.transport.send_request(
                endpoint="submit",
                method="POST",
                data=envelope,
                params={"verify": verify, "wait": wait},
            )
            return [Submission(**res) for res in response]
        except Exception as e:
            raise AccumulateError(f"Submission failed: {e}")

    async def faucet(self, account: str, token_url: Optional[str] = None) -> Submission:
        """Request tokens from the Accumulate faucet."""
        if not account:
            raise ValueError("Account URL must be provided.")
        try:
            response = await self.transport.send_request(
                endpoint="faucet",
                method="POST",
                data={"account": account},
                params={"token": token_url} if token_url else {},
            )
            return Submission(**response)
        except Exception as e:
            raise AccumulateError(f"Faucet request failed: {e}")

    async def validate(self, envelope: Dict[str, Any], full: bool = False) -> Dict[str, Any]:
        """Validate a transaction envelope against the Accumulate network."""
        try:
            return await self.transport.send_request(
                endpoint="validate",
                method="POST",
                data=envelope,
                params={"full": full},
            )
        except Exception as e:
            raise AccumulateError(f"Validation failed: {e}")

    async def close(self):
        """Close the transport connection."""
        await self.transport.close()
