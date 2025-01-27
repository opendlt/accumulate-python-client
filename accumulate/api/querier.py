# accumulate-python-client\accumulate\api\querier.py 

import logging
import importlib
from typing import Optional, Any, List, Type, TypeVar
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from accumulate.models.enums import QueryType
from accumulate.api.exceptions import AccumulateError
from accumulate.models.events import ErrorEvent, BlockEvent, GlobalsEvent

from accumulate.models.records import (
    Record,
    RecordRange,
    AccountRecord,
    MessageRecord,
    ChainEntryRecord,
    ChainRecord,
    range_of,
)
from accumulate.models.enums import EVENT_TYPE_MAPPING
from accumulate.models.queries import Query
from accumulate.utils.url import URL
from accumulate.api.context import RequestContext

T = TypeVar("T", bound=Record)


class Querier:
    """Handles queries related to accounts, transactions, records, and events."""

    def __init__(self, transport):
        self.transport = transport
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.DEBUG)

    async def query(self, ctx: RequestContext, scope: str, query: Query, result_type: Type[T]) -> T:
        """Submit a generic query to the Accumulate network."""
        if not query.is_valid():
            self.logger.error("Invalid query: %s", query)
            raise ValueError("Invalid query.")

        message = {
            "action": "Query",
            "params": {"scope": scope, "type": query.query_type.name, "params": query.to_dict()},
        }

        try:
            self.logger.debug("Sending query: %s", message)
            response = await self.transport.send_message(ctx, message)
            self.logger.debug("Query response: %s", response)
            return self._deserialize_response(response, result_type)
        except Exception as e:
            error_message = f"Query failed: {e}"
            self.logger.error(error_message)
            raise AccumulateError(error_message) from e





    async def query_record(self, ctx: RequestContext, scope: URL, query: Query, result_type: Type[T]) -> T:
        """Submit a query for a specific record type."""
        try:
            self.logger.debug("Querying record for scope: %s, query: %s, result_type: %s", scope, query, result_type)
            response = await self.query(ctx, str(scope), query, result_type)  # Pass result_type here
            self.logger.debug("Record query response: %s", response)
            return self._deserialize_response(response, result_type)
        except Exception as e:
            self.logger.error("Error in query_record: %s", e)
            raise

    async def query_events(self, ctx: RequestContext, scope: URL, query: Query) -> List[Record]:
        """Query for events."""
        try:
            self.logger.debug("Querying events for scope: %s, query: %s", scope, query)
            response = await self.query(ctx, str(scope), query, RecordRange)
            self.logger.debug("Event query response: %s", response)

            events = []
            for record in response.records:
                if not isinstance(record, Record):
                    raise AccumulateError(f"Unexpected record type in events: {type(record)}")

                event_type = record.record_type
                event_class_path = EVENT_TYPE_MAPPING.get(event_type)
                if not event_class_path:
                    # Log and skip unknown event types
                    self.logger.warning(f"Skipping unknown event type: {event_type}")
                    continue

                # Dynamically resolve the class
                module_name, class_name = event_class_path.rsplit(".", 1)
                module = importlib.import_module(module_name)
                event_class = getattr(module, class_name)

                events.append(event_class.from_dict(record.to_dict()))

            return events
        except Exception as e:
            error_message = f"Error in query_events: {e}"
            self.logger.error(error_message)
            raise AccumulateError(error_message) from e





    def _deserialize_response(self, data: Any, result_type: Type[T]) -> T:
        """Deserialize a response into the expected result type."""
        try:
            self.logger.debug("Deserializing response: %s into type: %s", data, result_type)

            if issubclass(result_type, RecordRange):
                if not isinstance(data, RecordRange):
                    raise AccumulateError(f"Expected RecordRange, got {type(data)}") #

                # Use range_of for validation
                return range_of(data, getattr(data, "item_type", Record))

            if not isinstance(data, result_type):
                raise AccumulateError(f"Expected {result_type}, got {type(data)}")
            return data
        except Exception as e:
            self.logger.error("Deserialization failed: %s", e)
            raise AccumulateError(f"Deserialization failed: {e}")

    async def query_generic(self, ctx: RequestContext, scope: URL, query: Query, result_type: Type[T]) -> T:
        """Generic query handler."""
        response = await self.query(ctx, str(scope), query, result_type)  # Pass result_type here
        return self._deserialize_response(response, result_type)

    async def query_account(self, ctx: RequestContext, account: URL, query: Query) -> AccountRecord:
        """Query account details."""
        result = await self.query_record(ctx, account, query, AccountRecord) #
        if not isinstance(result, AccountRecord): #
            raise AccumulateError(f"Unexpected response type: {type(result)} (expected AccountRecord)") #
        return result #

    async def query_chain(self, ctx: RequestContext, scope: URL, query: Query) -> ChainRecord:
        """Query chain details."""
        result = await self.query_record(ctx, scope, query, ChainRecord)
        if not isinstance(result, ChainRecord):
            raise AccumulateError(f"Unexpected response type: {type(result)} (expected ChainRecord)") #
        return result

    async def query_chain_entries(self, ctx: RequestContext, scope: URL, query: Query) -> RecordRange[ChainEntryRecord]:
        """Query chain entries."""
        result = await self.query_record(ctx, scope, query, RecordRange)
        if not isinstance(result, RecordRange) or not all(isinstance(r, ChainEntryRecord) for r in result.records):
            raise AccumulateError(f"Unexpected response type: {type(result)} or invalid nested types") #
        return result

    async def query_transaction(self, ctx: RequestContext, txid: URL, query: Query) -> MessageRecord:
        """Query transaction details."""
        self.logger.debug("Querying transaction for: %s with query: %s", txid, query) #
        result = await self.query_record(ctx, txid, query, MessageRecord) #
        if not isinstance(result, MessageRecord): #
            raise AccumulateError(f"Unexpected response type: {type(result)} (expected MessageRecord)") #
        return result #


    async def query_block(self, ctx: RequestContext, scope: URL, query: Query) -> RecordRange:
        """Query block details."""
        self.logger.debug("Querying block for: %s with query: %s", scope, query) #
        result = await self.query_record(ctx, scope, query, RecordRange) #
        if not isinstance(result, RecordRange): #
            raise AccumulateError(f"Unexpected response type: {type(result)} (expected RecordRange)") #
        return result

