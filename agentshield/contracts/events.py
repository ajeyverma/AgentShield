"""
AgentShield AI — Unified Security Event Contract (Phase 11).

Defines the centralized, typed schema for all security events emitted across
AgentShield components (Execution Gateway, MCP Gateway, Security Engine,
Threat Detection, Approvals, Policies, Emergency Controls, and Identity).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentshield.security.sanitization import redact_secrets


class EventSeverity(str, Enum):
    """Normalized security event severity levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    WARNING = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventComponent(str, Enum):
    """Source components generating security events."""
    GATEWAY = "execution_gateway"
    MCP_GATEWAY = "mcp_gateway"
    SECURITY_ENGINE = "security_engine"
    THREAT_DETECTION = "threat_detection"
    APPROVAL = "approval_service"
    APPROVALS = "approval_service"
    POLICIES = "policy_service"
    EMERGENCY = "emergency_service"
    IDENTITY = "identity_service"
    AUDIT = "audit_service"
    SYSTEM = "system"


class SecurityEvent(BaseModel):
    """The authoritative unified security event emitted across the platform."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this specific event generated server-side.",
    )
    event_version: str = Field(
        default="1.0",
        description="Schema version of this event contract.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the event occurred.",
    )
    tenant_id: str = Field(
        default="default",
        description="Tenant or organization identifier owning the affected entity.",
    )
    actor_id: str = Field(
        default="system",
        description="Identifier of user, agent, or service initiating the action.",
    )
    agent_id: str | None = Field(
        default=None,
        description="Identifier of the AI agent involved, if applicable.",
    )
    integration_type: str | None = Field(
        default=None,
        description="Framework or protocol integration (e.g. OpenAI, Claude, LangGraph, CrewAI, ADK, MCP, API).",
    )
    session_id: str | None = Field(
        default=None,
        description="Active session or connection identifier.",
    )
    request_id: str | None = Field(
        default=None,
        description="Originating request ID.",
    )
    execution_id: str | None = Field(
        default=None,
        description="Correlated execution ID if related to a tool run.",
    )
    correlation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="End-to-end correlation ID linking related cross-component calls.",
    )
    trace_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Distributed trace ID (32-character hex).",
    )
    span_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:16],
        description="Component span ID (16-character hex).",
    )
    parent_span_id: str | None = Field(
        default=None,
        description="Parent span ID for causal tracing.",
    )
    event_type: str = Field(
        default="security.event",
        description="Dot-notated classification string (e.g. tool.execution_blocked, threat.detected).",
    )
    severity: EventSeverity = Field(
        default=EventSeverity.INFO,
        description="Security severity level.",
    )
    source_component: EventComponent = Field(
        default=EventComponent.GATEWAY,
        description="Subsystem that generated the event.",
    )
    action: str = Field(
        default="unknown",
        description="Operation performed or attempted (e.g. tool_call, evaluate, approve).",
    )
    decision: str | None = Field(
        default=None,
        description="Security authorization outcome if evaluated (ALLOW, BLOCK, ASK_HUMAN).",
    )
    resource: str | None = Field(
        default=None,
        description="Target resource or object affected (path, URL, database, tool).",
    )
    sanitized_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized metadata and parameters scrubbed of sensitive secrets.",
    )

    def sanitize_metadata(self) -> None:
        """Ensure all stored metadata is scrubbed of credentials."""
        if self.sanitized_metadata:
            self.sanitized_metadata = redact_secrets(self.sanitized_metadata)
