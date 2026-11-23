"""
AgentShield AI — MCP Protocol Validation (Phase 8).
"""

from __future__ import annotations

import json
from typing import Any

from agentshield.mcp_gateway.exceptions import MCPProtocolError
from agentshield.mcp_gateway.protocol.messages import INVALID_PARAMS, INVALID_REQUEST, PARSE_ERROR

SUPPORTED_METHODS = {
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "resources/templates/list",
    "prompts/list",
    "prompts/get",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
}


def validate_jsonrpc_payload(raw_data: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """
    Parse and validate raw incoming data as a JSON-RPC 2.0 message.
    """
    if isinstance(raw_data, (str, bytes)):
        try:
            payload = json.loads(raw_data)
        except Exception as e:
            raise MCPProtocolError(f"Parse error: invalid JSON: {e}", rpc_error_code=PARSE_ERROR)
    elif isinstance(raw_data, dict):
        payload = raw_data
    else:
        raise MCPProtocolError("Invalid payload type, expected JSON object", rpc_error_code=INVALID_REQUEST)

    if not isinstance(payload, dict):
        raise MCPProtocolError("JSON-RPC message must be an object", rpc_error_code=INVALID_REQUEST)

    if payload.get("jsonrpc") != "2.0":
        raise MCPProtocolError("Missing or invalid 'jsonrpc' version field (must be '2.0')", rpc_error_code=INVALID_REQUEST)

    method = payload.get("method")
    # Notifications or requests must have method if it's an incoming client call
    is_response = "result" in payload or "error" in payload
    if not is_response and not isinstance(method, str):
        raise MCPProtocolError("Missing or invalid 'method' field in JSON-RPC request", rpc_error_code=INVALID_REQUEST)

    params = payload.get("params")
    if params is not None and not isinstance(params, (dict, list)):
        raise MCPProtocolError("Params field must be an object or array", rpc_error_code=INVALID_PARAMS)

    return payload
