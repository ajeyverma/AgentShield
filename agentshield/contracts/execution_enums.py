"""
AgentShield AI — Execution Status Enums (Phase 6).
"""

from enum import Enum


class ExecutionStatus(str, Enum):
    """Lifecycle state of a tool execution in the Controlled Execution Gateway."""

    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    EVALUATING = "EVALUATING"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
