"""
AgentShield AI — OpenAI Agents SDK Integration Schemas (Phase 7).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class OpenAIToolCall(BaseModel):
    """Normalized representation of an intercepted OpenAI tool call."""

    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    action_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentShieldToolResult(BaseModel):
    """Standardized result returned to the OpenAI model after gateway evaluation."""

    status: str  # "SUCCESS", "BLOCKED", "PENDING_APPROVAL", "FAILED"
    decision: str = "BLOCK"  # "ALLOW", "BLOCK", "ASK_HUMAN"
    execution_id: str | None = None
    approval_id: str | None = None
    result: Any | None = None
    error_code: str | None = None
    error_message: str | None = None
    message: str | None = None

    def to_model_output(self) -> dict[str, Any]:
        """Convert into a structured dictionary suitable for returning to the OpenAI agent."""
        if self.status in ("SUCCESS", "COMPLETED"):
            return {
                "status": "SUCCESS",
                "result": self.result,
                "execution_id": self.execution_id,
            }
        elif self.status == "BLOCKED":
            return {
                "status": "BLOCKED",
                "error": self.error_message or "Operation blocked by AgentShield security policy.",
                "execution_id": self.execution_id,
            }
        elif self.status == "PENDING_APPROVAL":
            return {
                "status": "PENDING_APPROVAL",
                "execution_id": self.execution_id,
                "approval_id": self.approval_id,
                "message": (
                    f"This operation has been paused by AgentShield and requires human approval before proceeding. "
                    f"Execution ID: {self.execution_id}, Approval ID: {self.approval_id}."
                ),
            }
        else:
            return {
                "status": "FAILED",
                "error_code": self.error_code or "EXECUTION_FAILED",
                "error": self.error_message or "Tool execution failed on AgentShield gateway.",
                "execution_id": self.execution_id,
            }


class OpenAIAgentSessionSummary(BaseModel):
    """Observability summary of an AgentShield-monitored agent session."""

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    agent_name: str
    model_name: str
    total_tool_calls: int = 0
    allowed_count: int = 0
    blocked_count: int = 0
    approval_count: int = 0
    tool_invocations: list[dict[str, Any]] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
