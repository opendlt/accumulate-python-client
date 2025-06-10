# accumulate-python-client\accumulate\api\client.py 

import accumulate.api.client as client_module
import json
import os
import inspect
import logging
from typing import Any, Dict, List, Optional
from accumulate.api.transport import RoutedTransport
from accumulate.api.exceptions import AccumulateError
from accumulate.models.enums import QueryType
from accumulate.models.submission import Submission
from accumulate.models.service import FindServiceOptions, FindServiceResult
from accumulate.models.records import (
    ChainEntryRecord, KeyRecord, Record, RecordRange, SignatureSetRecord,
    TxIDRecord, UrlRecord, AccountRecord, ChainRecord, MessageRecord
)
from accumulate.models.queries import Query
from accumulate.models.signature_types import SignatureType
from accumulate.config import get_accumulate_rpc_url
from accumulate.utils.conversion import camel_to_snake
from accumulate.models.enums import RecordType

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AccumulateClient")

# File to store request ID counter
ID_COUNTER_FILE = "rpc_id_counter.json"

def load_counter() -> int:
    """Load the last used request ID from file or start at 1 if missing."""
    if os.path.exists(ID_COUNTER_FILE):
        with open(ID_COUNTER_FILE, "r") as f:
            return json.load(f).get("id", 1)
    return 1

def save_counter(counter: int):
    """Save the current counter value to the file."""
    with open(ID_COUNTER_FILE, "w") as f:
        json.dump({"id": counter}, f)

class AccumulateClient:
    """Client for interacting with the Accumulate JSON-RPC API with a persistent auto-incrementing request ID."""

    def __init__(self, base_url: str = None):
        self.base_url = base_url or get_accumulate_rpc_url()
        self.transport = RoutedTransport(self.base_url)
        self._id_counter = load_counter()  # Load last used ID

    async def json_rpc_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a JSON-RPC request with an auto-incrementing ID stored persistently."""
        rpc_id = self._id_counter
        self._id_counter += 1
        save_counter(self._id_counter)  # Save new counter value

        json_rpc_payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": rpc_id,
        }

        logger.info(f"RPC Request: {json_rpc_payload}")

        try:
            response = await self.transport.send_request(endpoint="v3", method="POST", data=json_rpc_payload)

            logger.info(f"RPC Response: {response}")

            if "error" in response:
                raise AccumulateError(f"JSON-RPC request failed ({method}): {response['error'].get('message', 'Unknown error')}")

            return response.get("result", {})

        except Exception as e:
            logger.error(f"JSON-RPC request failed ({method}): {e}")
            raise AccumulateError(f"JSON-RPC request failed ({method}): {e}")


    async def submit(self, envelope: Dict[str, Any], verify: bool = True, wait: bool = True) -> Dict[str, Any]:
        """
        Submit a transaction to the Accumulate network.

        Args:
            envelope (Dict[str, Any]): The transaction envelope containing transactions and signatures.
            verify (bool, optional): If True, verifies the envelope before submission. Defaults to True.
            wait (bool, optional): If True, blocks until submission is confirmed or rejected. Defaults to True.

        Returns:
            Dict[str, Any]: The API response containing transaction details.
        """
        if not isinstance(envelope, dict):
            raise ValueError("Envelope must be a dictionary.")

        #  Ensure the envelope has "signatures" (FIRST in order)
        if "signatures" not in envelope or not isinstance(envelope["signatures"], list) or not envelope["signatures"]:
            raise ValueError("Envelope must contain at least one signature in a list.")

        #  Ensure "transaction" is correctly structured (SECOND in order)
        if "transaction" not in envelope or not isinstance(envelope["transaction"], list) or not envelope["transaction"]:
            raise ValueError("Envelope must contain at least one transaction in a list.")

        #  Validate transaction structure
        for txn in envelope["transaction"]:
            if not isinstance(txn, dict):
                raise ValueError("Each transaction must be a dictionary.")
            
            if "header" not in txn or not isinstance(txn["header"], dict):
                raise ValueError("Each transaction must contain a 'header' as a dictionary.")
            
            if "body" not in txn or not isinstance(txn["body"], dict):
                raise ValueError("Each transaction must contain a 'body' as a dictionary.")

            #  Ensure transactionHash (if exists) is properly formatted
            if "transactionHash" in txn and not isinstance(txn["transactionHash"], str):
                raise ValueError("Transaction hash must be a raw hex string.")

        #  Order envelope fields correctly
        ordered_envelope = {
            "signatures": envelope["signatures"],  # Signatures First
            "transaction": envelope["transaction"],  # Transactions Second
        }

        #  Include messages if they exist (LAST in order)
        if "messages" in envelope and isinstance(envelope["messages"], list):
            ordered_envelope["messages"] = envelope["messages"]

        params = {
            "envelope": ordered_envelope,
            "verify": verify,
            "wait": wait,
        }

        #  Debugging Before JSON Serialization
        for sig in envelope["signatures"]:
            if inspect.iscoroutine(sig):
                raise RuntimeError(f" Signature contains an unawaited coroutine: {sig}")

        json_params = json.dumps(params)  # Convert Python dict to JSON string
        formatted_params = json.loads(json_params)  # Convert JSON string back to dict (ensures double quotes)

        #  Log the final envelope before submission
        logger.info(" Debug: Final Submission Payload")
        logger.info(json.dumps(formatted_params, indent=2))

        return await self.json_rpc_request("submit", formatted_params)


    async def validate(self, envelope: Dict[str, Any], full: bool = False) -> Dict[str, Any]:
        """Validate a transaction envelope against the Accumulate network using JSON-RPC"""
        params = {"envelope": envelope, "full": full}
        return await self.json_rpc_request("validate", params)


    async def query_block(self, block_type: str, index: Optional[int] = None, start: Optional[int] = None, count: Optional[int] = None) -> dict:
        """
        Query a minor or major block.

        Args:
            block_type (str): Either "minor" or "major"
            index (Optional[int]): Block index (if querying a specific block)
            start (Optional[int]): Start index for range queries
            count (Optional[int]): Number of blocks to retrieve in range queries

        Returns:
            dict: JSON response from the API
        """
        if block_type not in ["minor", "major"]:
            raise ValueError("Invalid block type. Must be 'minor' or 'major'.")

        params = {}

        if index is not None:
            #  Query a specific minor or major block
            url = f"{self.transport.base_url}/block/{block_type}/{index}"
            
            if block_type == "major":
                #  Fetch the first 3 minor blocks within the major block
                params["minor_start"] = 0
                params["minor_count"] = 3
                params["omit_empty"] = True  # Exclude empty minor blocks
                
        else:
            #  Query a block range
            url = f"{self.transport.base_url}/block/{block_type}"
            if start is not None:
                params["start"] = start
            if count is not None:
                params["count"] = count

        logger.info(f" HTTP Request: GET {url} with params {params}")

        response = await self.transport.send_request(endpoint=url, method="GET", params=params)

        if not response:
            logger.error(f" API request returned no response.")
            raise AccumulateError(f"Block query failed: No response received.")

        if response.get("error"):
            logger.error(f" API request failed: {response['error']}")
            raise AccumulateError(f"Block query failed: {response['error']['message']}")

        return response


    async def query(self, scope: str, query: Query) -> Record:
        """Submit a query to the Accumulate network using JSON-RPC."""
        if not query.is_valid():
            raise ValueError("Invalid query.")

        # Convert query to dictionary
        query_dict = query.to_dict()
        query_dict["queryType"] = query.query_type.to_rpc_format()

        params = {"scope": scope, "query": query_dict}

        #  DEBUG: Log raw API request
        logger.debug(f" Sending Query Request: {params}")

        response = await self.json_rpc_request("query", params)

        #  DEBUG: Log raw API response
        logger.debug(f" Raw API Response: {response} (Type: {type(response)})")

        #  If response is a string, try parsing it as JSON
        if isinstance(response, str):
            try:
                response = json.loads(response)
                logger.debug(f" Decoded String Response: {response}")
            except json.JSONDecodeError:
                raise AccumulateError(f"API returned an invalid JSON string: {response}")

        # Ensure response is a dictionary
        if not isinstance(response, dict):
            raise AccumulateError(f"Unexpected API response format: {response} (type: {type(response)})")

        #  Convert API response keys from camelCase to snake_case
        response = {camel_to_snake(k): v for k, v in response.items()}

        if "record_type" not in response:
            raise AccumulateError(f"Unexpected response format: {response}")

        record_type = response["record_type"]

        #  Ensure consistency with RecordType enum
        record_mapping = {
            RecordType.ACCOUNT.name.lower(): AccountRecord,
            RecordType.CHAIN.name.lower(): ChainRecord,
            RecordType.MESSAGE.name.lower(): MessageRecord,
            RecordType.CHAIN_ENTRY.name.lower(): ChainEntryRecord,
            RecordType.KEY.name.lower(): KeyRecord,
            RecordType.SIGNATURE_SET.name.lower(): SignatureSetRecord,
            RecordType.URL.name.lower(): UrlRecord,
            RecordType.TX_ID.name.lower(): TxIDRecord,
            RecordType.RANGE.name.lower(): RecordRange,
            "directory": RecordRange,  # Some APIs might return this as 'directory'
        }

        record_cls = record_mapping.get(record_type, Record)  # Default to Record if unknown

        #  Ensure return type is correct
        record_obj = record_cls.from_dict(response)
        logger.debug(f" Processed Query Response: {record_obj} (Type: {type(record_obj)})")

        return record_obj  # This should return an object with is_valid()


    async def search(self, account_id: str, search_type: str, value: str, extra_params: Optional[Dict[str, Any]] = None) -> dict:
        """
        Search an account for an anchor, public key, or delegate using JSON-RPC.

        Args:
            account_id (str): The account ID to search within.
            search_type (str): The type of search. Must be 'anchor', 'publicKey', or 'delegate'.
            value (str): The value to search for (anchor hash, public key, or delegate URL).
            extra_params (Optional[Dict[str, Any]]): Additional query parameters.

        Returns:
            dict: JSON response from the API.
        """
        if search_type not in ["anchor", "publicKey", "delegate"]:
            raise ValueError("Invalid search type. Must be 'anchor', 'publicKey', or 'delegate'.")

        #  Ensure correct JSON-RPC format
        params = {
            "scope": account_id,
            "query": {
                "queryType": search_type,
                "value": value
            }
        }

        #  Merge optional parameters if provided
        if extra_params:
            params["query"].update(extra_params)

        logger.info(f" RPC Request: {params}")

        response = await self.json_rpc_request("search", params)

        if not response:
            logger.error(f" API request returned no response.")
            raise AccumulateError(f"Search query failed: No response received.")

        return response


    async def network_status(self) -> Dict[str, Any]:
        """
        Fetch the current network status from the Accumulate blockchain.

        Returns:
            Dict[str, Any]: JSON response containing network status details.
        """
        try:
            response = await self.json_rpc_request("network-status")

            if not response:
                logger.error("Network status query returned no response.")
                raise AccumulateError("Network status query failed: No response received.")

            logger.info(f"Network Status Response: {response}")
            return response

        except Exception as e:
            logger.error(f"Failed to fetch network status: {e}")
            raise AccumulateError(f"Network status query failed: {e}")


    async def faucet(self, account: str, token_url: Optional[str] = None) -> Submission:
        """Request tokens from the Accumulate faucet using JSON-RPC"""
        if not account:
            raise ValueError("Account URL must be provided")

        params = {"account": account}
        if token_url:
            params["token"] = token_url

        response = await self.json_rpc_request("faucet", params)
        return Submission(**response)

    async def find_service(self, options: FindServiceOptions) -> List[FindServiceResult]:
        """Find available services on the Accumulate network using JSON-RPC"""
        params = options.to_dict()  # Converts to correct JSON-RPC format
        response = await self.json_rpc_request("find-service", params)

        return [FindServiceResult(
            peer_id=res.get("peer_id", ""),
            status=res.get("status", ""),
            addresses=res.get("addresses", [])
        ) for res in response]

    async def metrics(self) -> Dict[str, Any]:
        """Retrieve network metrics such as transactions per second using JSON-RPC"""
        return await self.json_rpc_request("metrics")

    async def list_snapshots(self) -> List[Dict[str, Any]]:
        """List available blockchain snapshots using JSON-RPC"""
        return await self.json_rpc_request("list-snapshots")

    async def close(self):
        """Close the transport connection"""
        logger.debug("🔌 Closing AccumulateClient transport connection")
        await self.transport.close()

