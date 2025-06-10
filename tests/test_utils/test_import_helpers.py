# tests\test_utils\test_import_helpers.py

import pytest
from unittest.mock import AsyncMock
import accumulate.utils.validation as validation_module
from accumulate.utils.import_helpers import (
    get_signer,
    is_lite_account_lazy,
    query_signer_version,
)
from accumulate.utils.url import URL


def test_get_signer_import_real():
    """Ensure get_signer returns the real Signer class."""
    from accumulate.signing.signer import Signer
    assert get_signer() is Signer


def test_is_lite_account_lazy_true(monkeypatch):
    """Test is_lite_account_lazy returns True when validation.is_lite_account returns True."""
    # Replace the real is_lite_account with one that always returns True
    monkeypatch.setattr(validation_module, "is_lite_account", lambda url: True)
    url = URL.parse("acc://whatever")
    assert is_lite_account_lazy(url) is True


def test_is_lite_account_lazy_false(monkeypatch):
    """Test is_lite_account_lazy returns False when validation.is_lite_account returns False."""
    monkeypatch.setattr(validation_module, "is_lite_account", lambda url: False)
    url = URL.parse("acc://whatever")
    assert is_lite_account_lazy(url) is False


@pytest.mark.asyncio
async def test_query_signer_version_with_client_lite(monkeypatch):
    """
    query_signer_version: when client is provided and
    is_lite_account_lazy returns True, should pick 'liteIdentity' path.
    """
    # Mock the client
    mock_client = AsyncMock()
    mock_client.json_rpc_request.return_value = {
        "result": {"account": {"signerVersion": 7}}
    }
    url = URL.parse("acc://lite.account")

    # Force the lazy check to True
    monkeypatch.setattr("accumulate.utils.import_helpers.is_lite_account_lazy", lambda u, c=None: True)

    version = await query_signer_version(url, client=mock_client)
    assert version == 7

    mock_client.json_rpc_request.assert_awaited_once_with(
        "query",
        {"scope": str(url), "query": {"queryType": "liteIdentity"}},
    )
    mock_client.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_query_signer_version_with_client_default(monkeypatch):
    """
    query_signer_version: when client is provided and
    is_lite_account_lazy returns False, should pick 'default' path.
    """
    mock_client = AsyncMock()
    mock_client.json_rpc_request.return_value = {
        "result": {"account": {"signerVersion": 3}}
    }
    url = URL.parse("acc://notlite.acme")

    monkeypatch.setattr("accumulate.utils.import_helpers.is_lite_account_lazy", lambda u, c=None: False)

    version = await query_signer_version(url, client=mock_client)
    assert version == 3

    mock_client.json_rpc_request.assert_awaited_once_with(
        "query",
        {"scope": str(url), "query": {"queryType": "default"}},
    )
    mock_client.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_query_signer_version_with_exception(monkeypatch):
    """
    query_signer_version: if json_rpc_request raises, should return None
    and still close the client.
    """
    mock_client = AsyncMock()
    mock_client.json_rpc_request.side_effect = RuntimeError("network error")
    url = URL.parse("acc://broken.account")

    # Could be either branch; pick True
    monkeypatch.setattr("accumulate.utils.import_helpers.is_lite_account_lazy", lambda u, c=None: True)

    result = await query_signer_version(url, client=mock_client)
    assert result is None

    mock_client.close.assert_awaited_once()
