"""
AgentShield AI — Shared Integration Exceptions (Phase 9).
"""

from __future__ import annotations

import re
from typing import Any
from agentshield.core.exceptions import AgentShieldError
from agentshield.threat_detection.analyzers.content_analyzer import ContentAnalyzer


def redact_secrets(text: str) -> str:
    """Sanitize any sensitive credentials from exception messages and logging."""
    if not text:
        return ""
    # Scrub specific patterns: sk-..., agt_..., anthropic, google, bearer tokens
    text = re.sub(r"sk-[a-zA-Z0-9_\-\.]{10,}", "[REDACTED]", text)
    text = re.sub(r"agt_[a-zA-Z0-9_\-\.]{10,}", "[REDACTED]", text)
    text = re.sub(r"Bearer\s+[a-zA-Z0-9_\-\.]{10,}", "Bearer [REDACTED]", text)
    try:
        text, _ = ContentAnalyzer.redact_string(text)
    except Exception:
        pass
    return text


class IntegrationError(AgentShieldError):
    """Base exception for all framework integration errors."""

    def __init__(self, message: str, code: str = "INTEGRATION_ERROR", details: dict[str, Any] | None = None) -> None:
        safe_msg = redact_secrets(message)
        super().__init__(message=safe_msg, code=code)
        self.details = details or {}


class AuthenticationFailureError(IntegrationError):
    """Raised when agent credentials fail validation on the AgentShield gateway."""

    def __init__(self, message: str = "Agent authentication failed on AgentShield gateway.") -> None:
        super().__init__(message=message, code="AUTHENTICATION_FAILED")


class BackendUnavailableError(IntegrationError):
    """Raised when the AgentShield backend is unreachable (triggers fail-closed denial)."""

    def __init__(self, message: str = "AgentShield backend is unreachable. Action denied fail-closed.") -> None:
        super().__init__(message=message, code="BACKEND_UNAVAILABLE")


class ToolNotAllowedError(IntegrationError):
    """Raised when an agent attempts to invoke a tool outside its configured allowlist."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(
            message=f"Tool '{tool_name}' is not permitted by your AgentShield configuration allowlist.",
            code="TOOL_NOT_ALLOWED",
            details={"tool_name": tool_name},
        )


class SecurityPolicyBlockError(IntegrationError):
    """Raised when an action is explicitly blocked by AgentShield policy or threat detection."""

    def __init__(self, message: str, reasons: list[str] | None = None) -> None:
        super().__init__(
            message=message,
            code="SECURITY_POLICY_BLOCK",
            details={"reasons": reasons or []},
        )


class ApprovalPendingError(IntegrationError):
    """Raised when an action is paused pending human review."""

    def __init__(self, approval_id: str, message: str = "Action paused: human approval required.") -> None:
        super().__init__(
            message=message,
            code="APPROVAL_PENDING",
            details={"approval_id": approval_id},
        )
        self.approval_id = approval_id


class InvalidToolArgumentsError(IntegrationError):
    """Raised when arguments provided by the agent fail schema or semantic validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="INVALID_TOOL_ARGUMENTS")


class FrameworkNotInstalledError(IntegrationError):
    """Raised when a requested AI agent framework package is not installed on the system."""

    def __init__(self, framework_name: str, package_name: str) -> None:
        super().__init__(
            message=f"Framework '{framework_name}' requires optional package '{package_name}' to be installed.",
            code="FRAMEWORK_NOT_INSTALLED",
            details={"framework": framework_name, "package": package_name},
        )
