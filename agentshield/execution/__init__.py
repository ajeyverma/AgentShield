"""
AgentShield AI — Execution Package Export (Phase 6).
"""

from agentshield.execution.adapters import (
    BaseToolAdapter,
    CalculatorAdapter,
    MockEmailAdapter,
    MockHttpAdapter,
    SandboxedFilesystemAdapter,
    ToolExecutionResult,
)
from agentshield.execution.authorization import ExecutionAuthorizationManager, authorization_manager
from agentshield.execution.enums import ExecutionStatus
from agentshield.execution.exceptions import (
    ActionNotFoundError,
    ApprovalVerificationError,
    ExecutionGatewayError,
    ExecutionTimeoutError,
    IdempotencyConflictError,
    InvalidArgumentsError,
    OutputSizeExceededError,
    ToolDisabledError,
    ToolNotFoundError,
)
from agentshield.execution.gateway import ExecutionGateway
from agentshield.execution.registry import ActionDefinition, ToolDefinition, ToolRegistry, tool_registry

__all__ = [
    "ExecutionStatus",
    "ExecutionGatewayError",
    "ToolNotFoundError",
    "ActionNotFoundError",
    "ToolDisabledError",
    "InvalidArgumentsError",
    "ExecutionTimeoutError",
    "OutputSizeExceededError",
    "ApprovalVerificationError",
    "IdempotencyConflictError",
    "ToolRegistry",
    "tool_registry",
    "ToolDefinition",
    "ActionDefinition",
    "BaseToolAdapter",
    "ToolExecutionResult",
    "CalculatorAdapter",
    "SandboxedFilesystemAdapter",
    "MockEmailAdapter",
    "MockHttpAdapter",
    "ExecutionAuthorizationManager",
    "authorization_manager",
    "ExecutionGateway",
]
