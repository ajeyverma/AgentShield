"""
AgentShield AI — MCP Gateway Exceptions (Phase 8).
"""

from __future__ import annotations

from typing import Any

from agentshield.core.exceptions import AgentShieldError


class MCPGatewayError(AgentShieldError):
    """Base exception for all MCP Gateway errors."""

    def __init__(
        self,
        message: str,
        code: str = "MCP_GATEWAY_ERROR",
        status_code: int = 500,
        rpc_error_code: int = -32603,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message=message, code=code)
        self.status_code = status_code
        self.rpc_error_code = rpc_error_code
        self.details = details or {}


class NotFoundError(AgentShieldError):
    """Raised when a requested resource is not found."""

    def __init__(self, resource_type: str = "Resource", resource_id: str = "") -> None:
        super().__init__(message=f"{resource_type} '{resource_id}' not found", code="NOT_FOUND")
        self.status_code = 404
        self.resource_type = resource_type
        self.resource_id = resource_id


class ValidationError(AgentShieldError):
    """Raised when request parameters fail domain validation."""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message=message, code="VALIDATION_ERROR")
        self.status_code = 400
        self.field = field


class MCPProtocolError(MCPGatewayError):
    """Raised when JSON-RPC or MCP protocol framing is invalid."""

    def __init__(self, message: str, rpc_error_code: int = -32600, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            code="MCP_PROTOCOL_ERROR",
            status_code=400,
            rpc_error_code=rpc_error_code,
            details=details,
        )


class MCPSecurityError(MCPGatewayError):
    """Base exception for security-related MCP Gateway violations."""

    def __init__(
        self,
        message: str,
        code: str = "MCP_SECURITY_VIOLATION",
        status_code: int = 403,
        rpc_error_code: int = -32002,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=status_code,
            rpc_error_code=rpc_error_code,
            details=details,
        )


class MCPBlockedError(MCPSecurityError):
    """Raised when an MCP operation is explicitly blocked by policy or threat detection."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            code="MCP_OPERATION_BLOCKED",
            status_code=403,
            rpc_error_code=-32000,
            details=details,
        )


class MCPApprovalRequiredError(MCPSecurityError):
    """Raised when an MCP operation requires human approval before proceeding."""

    def __init__(self, message: str, approval_id: str, details: dict[str, Any] | None = None) -> None:
        det = details or {}
        det["approval_id"] = approval_id
        super().__init__(
            message=message,
            code="MCP_APPROVAL_REQUIRED",
            status_code=202,
            rpc_error_code=-32001,
            details=det,
        )
        self.approval_id = approval_id


class MCPUntrustedCommandError(MCPSecurityError):
    """Raised when a client attempts to launch an unwhitelisted STDIO executable."""

    def __init__(self, command: str) -> None:
        super().__init__(
            message=f"Executable '{command}' is not in the allowed MCP gateway whitelist.",
            code="MCP_UNTRUSTED_COMMAND",
            status_code=403,
            rpc_error_code=-32002,
            details={"command": command},
        )


class MCPSSRFError(MCPSecurityError):
    """Raised when a remote MCP endpoint points to a forbidden/private network address."""

    def __init__(self, reason: str, endpoint: str) -> None:
        super().__init__(
            message=f"SSRF violation: {reason}",
            code="MCP_SSRF_BLOCKED",
            status_code=403,
            rpc_error_code=-32004,
            details={"endpoint": endpoint, "reason": reason},
        )


class MCPServerConnectionError(MCPGatewayError):
    """Raised when connection to an upstream external MCP server fails."""

    def __init__(self, server_id: str, message: str) -> None:
        super().__init__(
            message=f"Upstream MCP server '{server_id}' connection error: {message}",
            code="MCP_SERVER_CONNECTION_FAILED",
            status_code=502,
            rpc_error_code=-32003,
            details={"server_id": server_id, "error": message},
        )


class MCPTransportError(MCPGatewayError):
    """Raised when low-level transport stream communication fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            code="MCP_TRANSPORT_ERROR",
            status_code=502,
            rpc_error_code=-32003,
            details=details,
        )


class MCPResponseInspectionError(MCPSecurityError):
    """Raised when upstream response inspection detects an uncontainable security violation."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            code="MCP_RESPONSE_INSPECTION_FAILED",
            status_code=502,
            rpc_error_code=-32002,
            details=details,
        )
