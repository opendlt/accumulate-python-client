# accumulate\models\search.py

from typing import Any, Optional, Union, Dict
from accumulate.models.enums import QueryType
from accumulate.models.errors import AccumulateError
from accumulate.models.queries import Query

class SearchQuery(Query):
    """Base class for all search queries (Anchor, Public Key, Delegate)."""

    def __init__(self, query_type: QueryType, value: str, extra_params: Optional[Dict[str, Any]] = None):
        """
        Args:
            query_type (QueryType): The type of search query (anchor, publicKey, delegate).
            value (str): The value being searched (hash, public key, or delegate URL).
            extra_params (Optional[Dict[str, Any]]): Additional query parameters.
        """
        super().__init__(query_type)
        self.value = value
        self.extra_params = extra_params or {}

    def is_valid(self):
        """Validate the search query."""
        if not self.value:
            raise AccumulateError(f"{self.query_type.name} search requires a valid value.")

    def to_dict(self) -> dict:
        """Convert the search query into a dictionary that can be used with `client.search()`."""
        return {
            "value": self.value,
            "extra_params": self.extra_params
        }
    

class AnchorSearchQuery(SearchQuery):
    """Search for an anchor in an account."""

    def __init__(self, anchor: Union[bytes, str], include_receipt: Optional[bool] = None):
        """
        Args:
            anchor (Union[bytes, str]): The anchor value (hash) to search for.
            include_receipt (Optional[bool]): Whether to include a receipt in the response.
        """
        anchor_value = anchor.hex() if isinstance(anchor, bytes) else anchor
        extra_params = {"include_receipt": include_receipt} if include_receipt is not None else {}
        super().__init__(QueryType.ANCHOR_SEARCH, anchor_value, extra_params)

class PublicKeySearchQuery(SearchQuery):
    """Search for a public key in an account."""

    def __init__(self, public_key: str, key_type: Optional[str] = None):
        """
        Args:
            public_key (str): The public key, address, or public key hash.
            key_type (Optional[str]): The type of public key (e.g., 'ed25519', 'btc', 'eth').
        """
        extra_params = {"type": key_type} if key_type else {}
        super().__init__(QueryType.PUBLIC_KEY_SEARCH, public_key, extra_params)


class DelegateSearchQuery(SearchQuery):
    """Search for a delegate in an account."""

    def __init__(self, delegate_url: str):
        """
        Args:
            delegate_url (str): The URL of the delegate being searched.
        """
        super().__init__(QueryType.DELEGATE_SEARCH, delegate_url)
