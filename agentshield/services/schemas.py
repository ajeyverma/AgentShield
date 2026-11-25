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


class ApprovalApproveRequest(BaseModel):
    """Payload to approve a pending request."""

    comment: str | None = None


class ApprovalRejectRequest(BaseModel):
    """Payload to reject a pending request."""

    reason: str = Field(min_length=1, max_length=1000)


class ApprovalCancelRequest(BaseModel):
    """Payload to cancel an approval request."""

    reason: str | None = None


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
    execution_id: str | None = None
    tenant_id: str | None = None
    integration_type: str | None = None
    resource: str | None = None
    risk_score: float | None = None
    threat_findings_json: str | None = None
    canonical_argument_hash: str | None = None
    arguments_json: str | None = None
    reviewed_by: str | None = None
    reviewer_role: str | None = None
    reviewed_at: datetime | None = None
    review_comment: str | None = None
    rejection_reason: str | None = None


class ApprovalDetailResponse(ApprovalResponse):
    """Detailed approval record with sanitized arguments and parsed threat findings."""

    sanitized_arguments: dict[str, Any] = Field(default_factory=dict)
    threat_findings: list[dict[str, Any]] = Field(default_factory=list)


class ApprovalHistoryResponse(BaseModel):
    """Audit log entry for an approval state transition."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    approval_id: str
    user_id: str
    action: str
    previous_status: str | None = None
    new_status: str
    performed_by: str
    performer_role: str | None = None
    comment: str | None = None
    created_at: datetime


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
    priority: int = 100
    agent_scope: str = "*"
    integration_scope: str = "*"
    tool_scope: str = "*"
    action_scope: str = "*"
    resource_scope: str = "*"
    conditions_json: str | None = None
    decision: str = "ALLOW"
    rules_json: str | None = None
    approval_requirements_json: str | None = None


class PolicyUpdate(BaseModel):
    """Payload to update an existing policy."""

    name: str | None = None
    description: str | None = None
    category: str | None = None
    enforcement_mode: str | None = None
    is_enabled: bool | None = None
    priority: int | None = None
    agent_scope: str | None = None
    integration_scope: str | None = None
    tool_scope: str | None = None
    action_scope: str | None = None
    resource_scope: str | None = None
    conditions_json: str | None = None
    decision: str | None = None
    rules_json: str | None = None
    approval_requirements_json: str | None = None


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
    priority: int = 100
    agent_scope: str = "*"
    integration_scope: str = "*"
    tool_scope: str = "*"
    action_scope: str = "*"
    resource_scope: str = "*"
    conditions_json: str | None = None
    decision: str = "ALLOW"
    rules_json: str | None = None
    approval_requirements_json: str | None = None
    created_at: datetime
    updated_at: datetime


class PolicyVersionResponse(BaseModel):
    """Policy version snapshot."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    policy_id: str
    version: int
    name: str
    description: str | None = None
    category: str
    enforcement_mode: str
    priority: int
    decision: str
    agent_scope: str
    integration_scope: str
    tool_scope: str
    action_scope: str
    resource_scope: str
    conditions_json: str | None = None
    rules_json: str | None = None
    approval_requirements_json: str | None = None
    is_enabled: bool = True
    changed_by: str | None = None
    change_reason: str | None = None
    created_at: datetime


class PolicySimulationRequest(BaseModel):
    """Request for running synthetic policy simulation."""

    agent_id: str | None = None
    tool_name: str
    operation: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_id: str | None = None
    tenant_id: str | None = None
    integration_type: str = "API"
    resource: str | None = None


class PolicySimulationResponse(BaseModel):
    """Response of synthetic policy simulation."""

    simulated_decision: str
    decision_source: str
    matched_policy_id: str | None = None
    matched_policy_name: str | None = None
    matched_priority: int | None = None
    risk_score: float
    risk_level: str
    threat_findings: list[dict[str, Any]] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    executed_real_tool: bool = False


class PolicyConflictItem(BaseModel):
    """Detected conflict between two policies."""

    policy_a_id: str
    policy_a_name: str
    policy_a_priority: int
    policy_a_decision: str
    policy_b_id: str
    policy_b_name: str
    policy_b_priority: int
    policy_b_decision: str
    conflict_type: str
    details: str


# ---------------------------------------------------------------------------
# Emergency Controls
# ---------------------------------------------------------------------------


class EmergencyControlCreate(BaseModel):
    """Payload to activate an emergency control."""

    control_type: str
    target_identifier: str
    reason: str


class EmergencyControlRevoke(BaseModel):
    """Payload to revoke an emergency control."""

    reason: str = "Revoked by administrator"


class EmergencyControlResponse(BaseModel):
    """Public emergency control record."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    tenant_id: str | None = None
    control_type: str
    target_identifier: str
    is_active: bool
    reason: str
    activated_by: str
    activated_at: datetime
    revoked_by: str | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


class EmergencyStatusResponse(BaseModel):
    """Overview of active emergency security controls."""

    is_lockdown_active: bool
    active_controls_count: int
    active_controls: list[EmergencyControlResponse] = Field(default_factory=list)


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
    agent_id: str | None = None
    event_type: str
    resource_type: str
    resource_id: str | None = None
    description: str
    action: str | None = None
    result: str | None = None
    sequence_number: int | None = None
    current_hash: str | None = None
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


# ─── Phase 11: Monitoring, Auditing & Observability Schemas ───────────────


class SecurityEventResponse(BaseModel):
    """Schema representing a standardized security event."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    severity: str
    component: str
    tenant_id: str | None = None
    agent_id: str | None = None
    tool_name: str | None = None
    action: str | None = None
    decision: str | None = None
    status: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    correlation_id: str | None = None
    latency_ms: float | None = None
    details_json: str | None = None
    created_at: datetime


class AlertResponse(BaseModel):
    """Schema representing an active or resolved security alert."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_name: str
    title: str
    description: str
    severity: str
    status: str
    tenant_id: str | None = None
    agent_id: str | None = None
    trigger_count: int = 1
    evidence_json: str | None = None
    created_at: datetime
    updated_at: datetime


class AlertUpdateStatus(BaseModel):
    """Request payload to update an alert status."""

    status: str = Field(pattern="^(active|acknowledged|resolved|suppressed)$")


class IncidentCreate(BaseModel):
    """Payload to create a security incident."""

    title: str = Field(min_length=3, max_length=256)
    description: str = Field(min_length=3)
    severity: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    agent_id: str | None = None
    alert_id: str | None = None


class IncidentUpdateStatus(BaseModel):
    """Payload to transition incident status."""

    status: str = Field(pattern="^(OPEN|ACKNOWLEDGED|INVESTIGATING|RESOLVED|CLOSED)$")
    reason: str | None = None


class IncidentNoteCreate(BaseModel):
    """Payload to add a note to an incident."""

    note: str = Field(min_length=1)


class IncidentNoteResponse(BaseModel):
    """Incident note representation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    author_id: str
    note: str
    created_at: datetime


class IncidentHistoryResponse(BaseModel):
    """Incident status change audit entry."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    old_status: str
    new_status: str
    changed_by: str
    reason: str | None = None
    created_at: datetime


class IncidentResponse(BaseModel):
    """Incident summary representation."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    title: str
    description: str
    severity: str
    status: str
    agent_id: str | None = None
    alert_id: str | None = None
    assigned_to: str | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    closed_at: datetime | None = None


class IncidentDetailResponse(IncidentResponse):
    """Detailed incident response including attached notes and transition history."""

    notes: list[IncidentNoteResponse] = []
    history: list[IncidentHistoryResponse] = []


class AuditVerifyResponse(BaseModel):
    """Cryptographic audit chain verification result."""

    is_valid: bool
    verified_count: int
    broken_index: int | None = None
    expected_hash: str | None = None
    actual_hash: str | None = None
    message: str
    last_verified_at: datetime


class AuditCheckpointCreate(BaseModel):
    """Request payload to create a new cryptographic audit checkpoint."""

    notes: str | None = None


class AuditCheckpointResponse(BaseModel):
    """Audit checkpoint response."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    checkpoint_hash: str
    sequence_number: int
    entry_count: int
    created_at: datetime


class AuditExportResponse(BaseModel):
    """Export of verifiable audit trail."""

    entries_count: int
    head_hash: str | None = None
    is_valid: bool
    export_timestamp: datetime
    entries: list[dict[str, Any]]


class MetricsSummaryResponse(BaseModel):
    """Aggregated security and operational metrics."""

    counters: dict[str, int]
    gauges: dict[str, float]
    latency_percentiles: dict[str, dict[str, float]]
    collected_at: datetime


class SystemHealthResponse(BaseModel):
    """High-level system health and integrity response."""

    status: str
    database_connected: bool
    version: str
    audit_chain_valid: bool
    metrics_summary: dict[str, Any]
