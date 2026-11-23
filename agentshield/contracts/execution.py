"""
AgentShield AI — Execution Gateway Contracts (Phase 6).

Standardized Pydantic models for execution requests, authorization grants,
and tool responses.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from agentshield.contracts.execution_enums import ExecutionStatus


def compute_canonical_argument_hash(arguments: dict[str, Any]) -> str:
    """Compute deterministic SHA256 digest of normalized arguments."""
    try:
        serialized = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        serialized = str(sorted(arguments.items()))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class ExecutionRequest(BaseModel):
    """Normalized tool execution request submitted to the Controlled Execution Gateway."""

    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    agent_id: uuid.UUID = Field(..., description="[SERVER-DERIVED] Authenticated agent ID")
    user_id: str | None = Field(default=None, description="[SERVER-DERIVED] Authenticated user/tenant ID")
    tool_name: str = Field(..., min_length=1, max_length=64)
    tool_version: str = Field(default="1.0.0", max_length=32)
    action_name: str = Field(..., min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=128)
    request_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_name", "action_name")
    @classmethod
    def clean_names(cls, v: str) -> str:
        s = v.strip().lower()
        if not s:
            raise ValueError("Tool and action names must not be empty.")
        return s

    @property
    def canonical_argument_hash(self) -> str:
        return compute_canonical_argument_hash(self.arguments)


class ExecutionAuthorizationGrant(BaseModel):
    """Cryptographically bound, single-use server-side execution grant."""

    grant_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request_id: uuid.UUID
    agent_id: str
    user_id: str
    tool_name: str
    action_name: str
    argument_hash: str
    decision_id: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    is_used: bool = False

    def is_valid_for(self, request: ExecutionRequest) -> bool:
        """Verify that this grant matches the exact identity and arguments without tampering."""
        if self.is_used:
            return False
        if datetime.now(UTC) > self.expires_at:
            return False
        if str(request.request_id) != str(self.request_id):
            return False
        if str(request.agent_id) != str(self.agent_id):
            return False
        if request.user_id and str(request.user_id) != str(self.user_id):
            return False
        if request.tool_name != self.tool_name or request.action_name != self.action_name:
            return False
        if request.canonical_argument_hash != self.argument_hash:
            return False
        return True


class ToolExecutionResponse(BaseModel):
    """Standardized response returned by the Execution Gateway."""

    execution_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request_id: uuid.UUID
    agent_id: str
    tool_name: str
    action_name: str
    status: ExecutionStatus
    decision: str  # ALLOW, BLOCK, ASK_HUMAN
    decision_id: str | None = None
    approval_id: str | None = None
    approval_required: bool = False
    result: Any | None = None
    error_code: str | None = None
    error_message: str | None = None
    duration_ms: float | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = {"from_attributes": True}


class ExecutionApprovalRequest(BaseModel):
    """Payload submitted by authenticated human user to approve or reject a pending execution."""

    approval_notes: str | None = None


class ToolActionMetadata(BaseModel):
    """Metadata describing a specific supported tool action."""

    action_name: str
    description: str
    required_permissions: list[str] = Field(default_factory=list)
    argument_schema: dict[str, Any] = Field(default_factory=dict)


class ToolMetadataResponse(BaseModel):
    """Registered tool information returned by the Gateway."""

    tool_name: str
    tool_version: str
    description: str
    is_enabled: bool
    risk_classification: str
    timeout_seconds: float
    max_output_bytes: int
    actions: list[ToolActionMetadata]
