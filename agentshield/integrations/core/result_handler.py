"""
AgentShield AI — Unified Result Handler (Phase 9).
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from agentshield.integrations.core.exceptions import redact_secrets


class AgentShieldToolResult(BaseModel):
    """Normalized result returned from an AgentShield tool execution across all frameworks."""

    status: str = Field(..., description="Lifecycle execution status (e.g. COMPLETED, BLOCKED, PENDING_APPROVAL, FAILED)")
    decision: str = Field(..., description="Authoritative security decision (ALLOW, BLOCK, ASK_HUMAN)")
    execution_id: str | None = Field(default=None, description="Unique execution gateway record ID.")
    approval_id: str | None = Field(default=None, description="Approval ID if decision was ASK_HUMAN.")
    result: Any = Field(default=None, description="Sanitized result data from the controlled adapter.")
    error_code: str | None = Field(default=None, description="Machine-readable error code if failed or blocked.")
    error_message: str | None = Field(default=None, description="Human-readable explanation of error or block.")

    def is_allowed(self) -> bool:
        return self.decision == "ALLOW" and self.status == "COMPLETED"

    def is_blocked(self) -> bool:
        return self.decision == "BLOCK" or self.status == "BLOCKED"

    def is_pending_approval(self) -> bool:
        return self.decision == "ASK_HUMAN" or self.status == "PENDING_APPROVAL"

    def to_model_output(self) -> dict[str, Any]:
        """Format a safe dictionary structure suitable for passing back to LLM context."""
        if self.is_allowed():
            return {
                "success": True,
                "status": self.status,
                "data": self.result,
            }
        elif self.is_pending_approval():
            return {
                "success": False,
                "status": "PENDING_APPROVAL",
                "approval_id": self.approval_id,
                "message": (
                    f"Action paused: human authorization is required (Approval ID: {self.approval_id}). "
                    "Wait for human confirmation before re-submitting."
                ),
            }
        else:
            return {
                "success": False,
                "status": self.status,
                "error_code": self.error_code or "SECURITY_BLOCK",
                "message": redact_secrets(self.error_message or "Operation blocked by AgentShield security gateway."),
            }

    def to_text_output(self) -> str:
        """Format output as a string for frameworks that expect string responses."""
        import json
        return json.dumps(self.to_model_output())
