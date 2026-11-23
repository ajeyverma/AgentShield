"""
Tests for MCP Protocol Validation and JSON-RPC Framing (Phase 8).
"""

import pytest

from agentshield.mcp_gateway.exceptions import MCPProtocolError
from agentshield.mcp_gateway.protocol.messages import (
    GATEWAY_POLICY_BLOCK,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    make_jsonrpc_error,
    make_jsonrpc_notification,
    make_jsonrpc_response,
)
from agentshield.mcp_gateway.protocol.validation import validate_jsonrpc_payload


def test_valid_jsonrpc_request():
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    res = validate_jsonrpc_payload(payload)
    assert res["jsonrpc"] == "2.0"
    assert res["method"] == "tools/list"
    assert res["id"] == 1


def test_valid_json_string():
    raw = '{"jsonrpc": "2.0", "id": "req-1", "method": "ping"}'
    res = validate_jsonrpc_payload(raw)
    assert res["id"] == "req-1"
    assert res["method"] == "ping"


def test_missing_jsonrpc_version():
    payload = {"id": 1, "method": "tools/list"}
    with pytest.raises(MCPProtocolError) as exc_info:
        validate_jsonrpc_payload(payload)
    assert exc_info.value.rpc_error_code == INVALID_REQUEST


def test_invalid_jsonrpc_version():
    payload = {"jsonrpc": "1.0", "id": 1, "method": "tools/list"}
    with pytest.raises(MCPProtocolError) as exc_info:
        validate_jsonrpc_payload(payload)
    assert exc_info.value.rpc_error_code == INVALID_REQUEST


def test_invalid_json_string():
    raw = '{"jsonrpc": "2.0", "id": 1, "method":'
    with pytest.raises(MCPProtocolError) as exc_info:
        validate_jsonrpc_payload(raw)
    assert exc_info.value.rpc_error_code == PARSE_ERROR


def test_missing_method_in_request():
    payload = {"jsonrpc": "2.0", "id": 1}
    with pytest.raises(MCPProtocolError) as exc_info:
        validate_jsonrpc_payload(payload)
    assert exc_info.value.rpc_error_code == INVALID_REQUEST


def test_invalid_params_type():
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "not-an-object"}
    with pytest.raises(MCPProtocolError) as exc_info:
        validate_jsonrpc_payload(payload)
    assert exc_info.value.rpc_error_code == INVALID_PARAMS


def test_make_jsonrpc_response():
    resp = make_jsonrpc_response("req-123", {"tools": []})
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "req-123"
    assert resp["result"] == {"tools": []}


def test_make_jsonrpc_error():
    err = make_jsonrpc_error("req-123", GATEWAY_POLICY_BLOCK, "Blocked by policy", data={"risk": 90.0})
    assert err["jsonrpc"] == "2.0"
    assert err["id"] == "req-123"
    assert err["error"]["code"] == GATEWAY_POLICY_BLOCK
    assert err["error"]["message"] == "Blocked by policy"
    assert err["error"]["data"]["risk"] == 90.0


def test_make_jsonrpc_notification():
    notif = make_jsonrpc_notification("notifications/initialized")
    assert notif["jsonrpc"] == "2.0"
    assert notif["method"] == "notifications/initialized"
    assert "id" not in notif
