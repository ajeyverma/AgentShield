"""
AgentShield AI — JSON-RPC 2.0 Message Helpers (Phase 8).
"""

from __future__ import annotations

from typing import Any

# Standard JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# AgentShield Gateway specific error codes
GATEWAY_POLICY_BLOCK = -32000
GATEWAY_APPROVAL_REQUIRED = -32001
GATEWAY_SECURITY_VIOLATION = -32002
GATEWAY_UPSTREAM_ERROR = -32003
GATEWAY_SSRF_BLOCKED = -32004
GATEWAY_TIMEOUT = -32005


def make_jsonrpc_response(request_id: Any, result: Any) -> dict[str, Any]:
    """Build a compliant JSON-RPC 2.0 success response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def make_jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    data: Any | None = None,
) -> dict[str, Any]:
    """Build a compliant JSON-RPC 2.0 error response."""
    err: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": err,
    }


def make_jsonrpc_notification(method: str, params: Any | None = None) -> dict[str, Any]:
    """Build a compliant JSON-RPC 2.0 notification (no id)."""
    msg: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": method,
    }
    if params is not None:
        msg["params"] = params
    return msg
