"""
AgentShield AI — Execution Gateway Exceptions (Phase 6).
"""

from __future__ import annotations


class ExecutionGatewayError(Exception):
    """Base exception for all execution gateway errors."""

    def __init__(self, message: str, error_code: str = "EXECUTION_ERROR") -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class ToolNotFoundError(ExecutionGatewayError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(f"Tool '{tool_name}' is not registered or not found.", "TOOL_NOT_FOUND")
        self.tool_name = tool_name


class ActionNotFoundError(ExecutionGatewayError):
    def __init__(self, tool_name: str, action_name: str) -> None:
        super().__init__(f"Action '{action_name}' is not supported by tool '{tool_name}'.", "ACTION_NOT_FOUND")
        self.tool_name = tool_name
        self.action_name = action_name


class ToolDisabledError(ExecutionGatewayError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(f"Tool '{tool_name}' is currently disabled.", "TOOL_DISABLED")
        self.tool_name = tool_name


class InvalidArgumentsError(ExecutionGatewayError):
    def __init__(self, details: str) -> None:
        super().__init__(f"Invalid arguments: {details}", "INVALID_ARGUMENTS")


class ExecutionTimeoutError(ExecutionGatewayError):
    def __init__(self, timeout_sec: float) -> None:
        super().__init__(f"Tool execution timed out after {timeout_sec}s.", "TIMEOUT_EXCEEDED")


class OutputSizeExceededError(ExecutionGatewayError):
    def __init__(self, size_bytes: int, max_bytes: int) -> None:
        super().__init__(f"Output size {size_bytes} exceeds limit of {max_bytes} bytes.", "OUTPUT_SIZE_EXCEEDED")


class ApprovalVerificationError(ExecutionGatewayError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Approval verification failed: {reason}", "APPROVAL_VERIFICATION_FAILED")


class IdempotencyConflictError(ExecutionGatewayError):
    def __init__(self, key: str) -> None:
        super().__init__(f"Execution with idempotency key '{key}' already exists.", "IDEMPOTENCY_CONFLICT")
