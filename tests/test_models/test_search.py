# tests\test_models\test_search.py

import pytest

from accumulate.models.search import (
    SearchQuery,
    AnchorSearchQuery,
    PublicKeySearchQuery,
    DelegateSearchQuery,
)
from accumulate.models.enums import QueryType
from accumulate.models.errors import AccumulateError


def test_searchquery_to_dict_and_is_valid():
    # Non-empty value should be valid
    sq = SearchQuery(QueryType.PUBLIC_KEY_SEARCH, value="abc123", extra_params={"type": "eth"})
    assert sq.query_type == QueryType.PUBLIC_KEY_SEARCH
    assert sq.value == "abc123"
    assert sq.extra_params == {"type": "eth"}
    # to_dict should return correct structure
    d = sq.to_dict()
    assert d == {"value": "abc123", "extra_params": {"type": "eth"}}
    # is_valid should not raise for non-empty value
    assert sq.is_valid() is None

    # Empty value currently bubbles up an AttributeError in AccumulateError init
    sq_empty = SearchQuery(QueryType.DELEGATE_SEARCH, value="")
    with pytest.raises(AttributeError) as excinfo:
        sq_empty.is_valid()
    # The internal attempt to access code.description on a string fails
    assert "description" in str(excinfo.value)


def test_anchor_search_query_bytes_and_str():
    # Bytes input without include_receipt
    banchor = b"\x01\x02"
    aq = AnchorSearchQuery(banchor)
    # Value should be hex of bytes
    assert aq.value == banchor.hex()
    # Query type
    assert aq.query_type == QueryType.ANCHOR_SEARCH
    # extra_params empty when include_receipt None
    assert aq.extra_params == {}
    # to_dict reflects that
    assert aq.to_dict() == {"value": banchor.hex(), "extra_params": {}}

    # String input with include_receipt True
    sack = "deadbeef"
    aq2 = AnchorSearchQuery(sack, include_receipt=True)
    assert aq2.value == sack
    assert aq2.extra_params == {"include_receipt": True}
    # Test include_receipt False
    aq3 = AnchorSearchQuery(sack, include_receipt=False)
    assert aq3.extra_params == {"include_receipt": False}


def test_public_key_search_query():
    # Without key_type
    pkq = PublicKeySearchQuery("pubkeyvalue")
    assert pkq.query_type == QueryType.PUBLIC_KEY_SEARCH
    assert pkq.value == "pubkeyvalue"
    assert pkq.extra_params == {}
    assert pkq.to_dict() == {"value": "pubkeyvalue", "extra_params": {}}

    # With key_type
    pkq2 = PublicKeySearchQuery("pubkeyvalue", key_type="ed25519")
    assert pkq2.extra_params == {"type": "ed25519"}


def test_delegate_search_query_and_empty():
    dq = DelegateSearchQuery("acc://example.acme/delegate")
    assert dq.query_type == QueryType.DELEGATE_SEARCH
    assert dq.value == "acc://example.acme/delegate"
    assert dq.extra_params == {}
    assert dq.to_dict() == {"value": "acc://example.acme/delegate", "extra_params": {}}
    # Empty delegate_url currently leads to an AttributeError in AccumulateError init
    dq_empty = DelegateSearchQuery("")
    with pytest.raises(AttributeError) as ei:
        dq_empty.is_valid()
    assert "description" in str(ei.value)
