"""
AgentShield AI — Services Request & Response Schemas.

Pydantic schemas for dashboard, activity, threat, approval, policy,
audit log, and integration APIs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard pagination envelope."""

    items: list[T]
    total: int
    page: int
    size: int
    pages: int


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class DashboardSummary(BaseModel):
    """Aggregated real-time metrics for the authenticated user."""

    total_agents: int = 0
    active_agents: int = 0
    total_activities: int = 0
    actions_today: int = 0
    blocked_actions: int = 0
    pending_approvals: int = 0
    threats_total: int = 0
    threats_by_severity: dict[str, int] = Field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------


class ActivityCreate(BaseModel):
    """Payload to record an activity event."""

    request_id: str
    agent_id: str
    tool_name: str
    operation: str
    decision: str = "ALLOW"
    risk_level: str = "NONE"
    execution_status: str = "pending"
    arguments_summary: str | None = None


class ActivityResponse(BaseModel):
    """Public activity event record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    request_id: str
    user_id: str
    agent_id: str
    tool_name: str
    operation: str
    decision: str
    risk_level: str
    execution_status: str
    arguments_summary: str | None
    created_at: datetime


# ---------------------------------------------------------------------------
# Threat
# ---------------------------------------------------------------------------


class ThreatCreate(BaseModel):
    """Payload to record a detected threat."""

    agent_id: str
    threat_type: str
    severity: str = "MEDIUM"
    description: str


class ThreatUpdate(BaseModel):
    """Payload to update threat status."""

    status: str = Field(pattern=r"^(open|investigating|resolved|dismissed)$")


class ThreatResponse(BaseModel):
    """Public threat event record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    agent_id: str
    threat_type: str
    severity: str
    description: str
    status: str
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------


class ApprovalCreate(BaseModel):
    """Payload to create a pending human approval request."""

    agent_id: str
    request_id: str
    tool_name: str
    operation: str
    risk_level: str = "MEDIUM"
    description: str
    expires_at: datetime | None = None


class ApprovalUpdate(BaseModel):
    """Update approval status (approve / reject only in Phase 3)."""

    status: str = Field(pattern=r"^(approved|rejected)$")


class ApprovalResponse(BaseModel):
    """Public approval request record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    agent_id: str
    request_id: str
    tool_name: str
    operation: str
    risk_level: str
    description: str
    status: str
    created_at: datetime
    expires_at: datetime | None


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class PolicyCreate(BaseModel):
    """Payload to create a security policy."""

    name: str = Field(min_length=2, max_length=128)
    description: str | None = None
    category: str = "general"
    enforcement_mode: str = "enforce"
    is_enabled: bool = True
    rules_json: str | None = None


class PolicyUpdate(BaseModel):
    """Payload to update an existing policy."""

    name: str | None = None
    description: str | None = None
    category: str | None = None
    enforcement_mode: str | None = None
    is_enabled: bool | None = None
    rules_json: str | None = None


class PolicyResponse(BaseModel):
    """Public policy configuration record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    name: str
    description: str | None
    category: str
    enforcement_mode: str
    is_enabled: bool
    version: int
    rules_json: str | None
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------


class AuditLogCreate(BaseModel):
    """Payload to record an audit log entry."""

    agent_id: str | None = None
    event_type: str
    resource_type: str
    resource_id: str | None = None
    description: str


class AuditLogResponse(BaseModel):
    """Public audit trail record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    agent_id: str | None
    event_type: str
    resource_type: str
    resource_id: str | None
    description: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------


class IntegrationCreate(BaseModel):
    """Payload to create an integration record."""

    integration_name: str = Field(min_length=2, max_length=128)
    integration_type: str = Field(min_length=2, max_length=64)
    status: str = "planned"
    configuration_metadata: str | None = None


class IntegrationUpdate(BaseModel):
    """Payload to update an integration record."""

    integration_name: str | None = None
    status: str | None = None
    configuration_metadata: str | None = None


class IntegrationResponse(BaseModel):
    """Public integration configuration record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    integration_name: str
    integration_type: str
    status: str
    configuration_metadata: str | None
    created_at: datetime
    updated_at: datetime
