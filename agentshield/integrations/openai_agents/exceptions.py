"""
AgentShield AI — OpenAI Agents SDK Integration Exceptions (Phase 7).
"""

from __future__ import annotations

import re
from typing import Any

from agentshield.core.exceptions import AgentShieldError


def redact_secrets(text: str) -> str:
    """Scrub raw API keys and agent credentials from exception messages and logs."""
    if not text:
        return ""
    # Redact OpenAI keys (sk-...)
    text = re.sub(r"sk-[a-zA-Z0-9_-]{20,}", "sk-***REDACTED***", text)
    # Redact Agent credentials (agt_...)
    text = re.sub(r"agt_[a-zA-Z0-9_-]{20,}", "agt_***REDACTED***", text)
    # Redact Bearer tokens
    text = re.sub(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer ***REDACTED***", text)
    return text


class OpenAIIntegrationError(AgentShieldError):
    """Base exception for all OpenAI Agents SDK integration errors."""

    def __init__(self, message: str, error_code: str = "OPENAI_INTEGRATION_ERROR", details: dict[str, Any] | None = None) -> None:
        safe_msg = redact_secrets(message)
        super().__init__(message=safe_msg, code=error_code)
        self.error_code = error_code
        self.details = details or {}


class BackendUnavailableError(OpenAIIntegrationError):
    """Raised when the AgentShield backend gateway cannot be reached (fail-closed)."""

    def __init__(self, message: str = "AgentShield backend gateway is unreachable; failing closed.") -> None:
        super().__init__(message=message, error_code="BACKEND_UNAVAILABLE")


class AuthenticationFailureError(OpenAIIntegrationError):
    """Raised when agent authentication against AgentShield fails."""

    def __init__(self, message: str = "AgentShield agent authentication failed.") -> None:
        super().__init__(message=message, error_code="AUTHENTICATION_FAILURE")


class ToolNotAllowedError(OpenAIIntegrationError):
    """Raised when an agent attempts to invoke a tool that is not in the allowlist."""

    def __init__(self, tool_name: str, allowed_tools: list[str]) -> None:
        super().__init__(
            message=f"Tool '{tool_name}' is not permitted by AgentShield allowlist. Allowed: {allowed_tools}",
            error_code="TOOL_NOT_ALLOWED",
            details={"tool_name": tool_name, "allowed_tools": allowed_tools},
        )


class SecurityPolicyBlockError(OpenAIIntegrationError):
    """Raised when an operation is blocked by an AgentShield policy."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            message=f"Agent action blocked by AgentShield security policy: {reason}",
            error_code="SECURITY_POLICY_BLOCK",
            details={"reason": reason},
        )


class ApprovalPendingError(OpenAIIntegrationError):
    """Raised when an action is paused awaiting human approval."""

    def __init__(self, approval_id: str, execution_id: str) -> None:
        super().__init__(
            message=f"Action paused pending human approval. Approval ID: {approval_id}, Execution ID: {execution_id}",
            error_code="APPROVAL_PENDING",
            details={"approval_id": approval_id, "execution_id": execution_id},
        )


class InvalidToolArgumentsError(OpenAIIntegrationError):
    """Raised when arguments provided by the model fail schema validation."""

    def __init__(self, tool_name: str, action_name: str, reason: str) -> None:
        super().__init__(
            message=f"Invalid arguments for {tool_name}.{action_name}: {reason}",
            error_code="INVALID_TOOL_ARGUMENTS",
            details={"tool_name": tool_name, "action_name": action_name, "reason": reason},
        )
