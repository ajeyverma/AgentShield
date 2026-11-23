"""
AgentShield AI — Unified Security Event Database Model (Phase 11).
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class SecurityEventModel(Base, UUIDPrimaryKeyMixin):
    """Persistent storage for unified security events."""

    __tablename__ = "security_events"

    event_version: Mapped[str] = mapped_column(String(16), default="1.0", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    integration_type: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    execution_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    trace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    span_id: Mapped[str] = mapped_column(String(32), nullable=False)
    parent_span_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="INFO", nullable=False, index=True)
    source_component: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_sec_events_tenant_time", "tenant_id", "timestamp"),
        Index("ix_sec_events_corr_id", "correlation_id"),
        Index("ix_sec_events_trace_span", "trace_id", "span_id"),
    )
