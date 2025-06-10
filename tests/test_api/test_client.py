# accumulate-python-client\tests\test_api\test_client.py

import warnings
import inspect
import os
import json
import asyncio
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from pathlib import Path

import accumulate.api.client as client_module
from accumulate.api.client import (
    AccumulateClient, load_counter, save_counter, ID_COUNTER_FILE
)
from accumulate.api.exceptions import AccumulateError
from accumulate.models.submission import Submission
from accumulate.models.service import FindServiceOptions, FindServiceResult
from accumulate.models.queries import Query
from accumulate.models.records import Record
from accumulate.utils.conversion import camel_to_snake

@pytest.fixture(autouse=True)
def tmp_counter_file(tmp_path, monkeypatch):
    # redirect the counter file to a temp path
    fake = tmp_path / "rpc_id_counter.json"
    monkeypatch.setattr(client_module, "ID_COUNTER_FILE", str(fake))
    # ensure no file exists initially
    if fake.exists():
        fake.unlink()
    return fake

def test_load_counter_no_file(tmp_counter_file):
    # when missing, defaults to 1
    assert load_counter() == 1

def test_save_and_load_counter(tmp_counter_file):
    # save 42, then load returns that
    save_counter(42)
    assert tmp_counter_file.exists()
    assert load_counter() == 42

@pytest.mark.asyncio
async def test_json_rpc_request_success_increments_id(tmp_counter_file, monkeypatch):
    # prepare client
    c = AccumulateClient(base_url="http://x")
    # stub transport
    sent = {}
    async def fake_send_request(endpoint, method, data):
        sent['endpoint'] = endpoint
        sent['method'] = method
        sent['data'] = data
        return {"result": {"foo": "bar"}}
    c.transport = AsyncMock(send_request=fake_send_request)
    # first call
    res1 = await c.json_rpc_request("test", {"a": 1})
    assert res1 == {"foo": "bar"}
    assert sent['endpoint'] == "v3"
    assert sent['method'] == "POST"
    # id should be 1
    assert sent['data']['id'] == 1
    # second call auto-increments
    res2 = await c.json_rpc_request("test2")
    assert sent['data']['id'] == 2

@pytest.mark.asyncio
async def test_json_rpc_request_error_in_payload(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    c.transport = AsyncMock(send_request=AsyncMock(return_value={"error": {"message": "oops"}}))
    with pytest.raises(AccumulateError, match=r"JSON-RPC request failed \(foo\): oops"):
        await c.json_rpc_request("foo")

@pytest.mark.asyncio
async def test_json_rpc_request_transport_exception(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    async def raise_it(*args, **kw):
        raise RuntimeError("transport down")
    c.transport = AsyncMock(send_request=raise_it)
    with pytest.raises(AccumulateError, match="JSON-RPC request failed \\(foo\\): transport down"):
        await c.json_rpc_request("foo")

#-------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_submit_validates_structure_and_unawaited_coroutine(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    # … all your existing validation tests …

    # === unawaited‐coro branch, using a real coroutine but suppressing the warning ===
    async def foo():
        """dummy coroutine"""
        return "ignored"

    coro = foo()
    # Catch and ignore the RuntimeWarning about an un-awaited coroutine
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=RuntimeWarning)
        with pytest.raises(RuntimeError, match="Signature contains an unawaited coroutine"):
            await c.submit(
                {"signatures": [coro],
                 "transaction": [{"header": {}, "body": {}}]}
            )
    # now close the coroutine so asyncio won’t warn
    coro.close()

    # valid envelope with messages
    good = {
        "signatures": [{"sig": "x"}],
        "transaction": [{"header": {}, "body": {}}],
        "messages": [{"foo": 1}],
    }
    called = {}
    async def fake_rpc(method, params):
        called["p"] = params
        return {"ok": True}

    monkeypatch.setattr(c, "json_rpc_request", fake_rpc)
    res = await c.submit(good, verify=False, wait=False)
    assert res == {"ok": True}

    # ordered envelope preserved
    assert called["p"]["envelope"]["signatures"] == good["signatures"]
    assert called["p"]["envelope"]["transaction"] == good["transaction"]
    assert called["p"]["envelope"]["messages"] == good["messages"]


#-------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_block_errors_and_success(monkeypatch):
    c = AccumulateClient(base_url="http://host")
    # invalid block type
    with pytest.raises(ValueError, match="Invalid block type"):
        await c.query_block("foo")
    # no response
    c.transport = AsyncMock(send_request=AsyncMock(return_value={}))
    with pytest.raises(AccumulateError, match="No response received"):
        await c.query_block("minor")
    # error in response
    c.transport = AsyncMock(send_request=AsyncMock(return_value={"error":{"message":"E"}}))
    with pytest.raises(AccumulateError, match="Block query failed: E"):
        await c.query_block("minor")
    # minor range
    c.transport = AsyncMock(send_request=AsyncMock(return_value={"data":"ok"}))
    out = await c.query_block("minor", start=5, count=7)
    assert out == {"data":"ok"}
    # minor by index
    out = await c.query_block("minor", index=3)
    assert out == {"data":"ok"}
    # major by index: params added
    called = {}
    async def fake_send(endpoint, method, params=None):
        called['endpoint'] = endpoint
        called['params'] = params
        return {"ok":1}
    c.transport = AsyncMock(send_request=fake_send)
    out = await c.query_block("major", index=11)
    assert out == {"ok":1}
    assert "/block/major/11" in called['endpoint']
    assert called['params']['minor_start']==0
    assert 'minor_count' in called['params']
    assert called['params']['omit_empty'] is True

#-------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_parsing_and_errors(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    # invalid query
    q = Mock(spec=Query)
    q.is_valid.return_value=False
    with pytest.raises(ValueError, match="Invalid query"):
        await c.query("scope", q)
    # valid but return string that is JSON
    q.is_valid.return_value=True
    q.to_dict.return_value={"k":"v"}
    q.query_type=Mock(to_rpc_format=Mock(return_value="T"))
    # stub json_rpc_request
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value='{"recordType":"foo","data":1}'))
    # check snake conversion and record instantiation
    rec = await c.query("s", q)
    assert isinstance(rec, Record)
    # invalid JSON string
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value="not json"))
    with pytest.raises(AccumulateError, match="invalid JSON string"):
        await c.query("s", q)
    # non-dict response
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value=[1,2,3]))
    with pytest.raises(AccumulateError, match="Unexpected API response format"):
        await c.query("s", q)
    # missing record_type
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value={"foo":"bar"}))
    with pytest.raises(AccumulateError, match="Unexpected response format"):
        await c.query("s", q)

#-------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_and_errors(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    # invalid type
    with pytest.raises(ValueError, match="Invalid search type"):
        await c.search("id", "bad", "v")
    # empty response
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value={}))
    with pytest.raises(AccumulateError, match="Search query failed"):
        await c.search("id", "anchor", "v")
    # valid response passes through
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value={"result":1}))
    out = await c.search("id", "anchor", "v", extra_params={"x":2})
    # search returns dict
    assert out == {"result":1}

#-------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_status_and_errors(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    # no response
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value={}))
    with pytest.raises(AccumulateError, match="No response received"):
        await c.network_status()
    # exception in json_rpc_request
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(side_effect=RuntimeError("down")))
    with pytest.raises(AccumulateError, match="Network status query failed: down"):
        await c.network_status()
    # valid
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value={"uptime": 123}))
    out = await c.network_status()
    assert out == {"uptime":123}

#-------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_faucet_and_find_service_and_close(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    # missing account
    with pytest.raises(ValueError, match="Account URL must be provided"):
        await c.faucet("")
    # valid
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value={"txid":"T","status":{}}))
    sub = await c.faucet("acc://1", token_url="tok")
    assert isinstance(sub, Submission)
    assert sub.txid == "T"
    # find_service
    opt = Mock(spec=FindServiceOptions)
    opt.to_dict.return_value = {"o":1}
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value=[{"peer_id":"p","status":"s","addresses":["a"]}]))
    res = await c.find_service(opt)
    assert isinstance(res[0], FindServiceResult)
    # close
    c.transport = AsyncMock(close=AsyncMock())
    await c.close()
    c.transport.close.assert_awaited()

#-------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_metrics_and_snapshots(monkeypatch):
    c = AccumulateClient(base_url="http://x")
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value={"m":1}))
    assert await c.metrics() == {"m":1}
    monkeypatch.setattr(c, "json_rpc_request", AsyncMock(return_value=[{"id":"s"}]))
    assert await c.list_snapshots() == [{"id":"s"}]
