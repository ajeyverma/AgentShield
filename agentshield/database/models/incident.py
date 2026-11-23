"""
AgentShield AI — Incident Management Database Models (Phase 11).
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class IncidentModel(Base, UUIDPrimaryKeyMixin):
    """Trackable security incident lifecycle entity."""

    __tablename__ = "incidents"

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False, index=True)
    affected_agent_ids_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    related_alert_ids_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    related_event_ids_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resolution_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_tenant_sev", "tenant_id", "severity"),
    )


class IncidentNoteModel(Base, UUIDPrimaryKeyMixin):
    """Investigation notes and findings attached to an incident."""

    __tablename__ = "incident_notes"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    author_id: Mapped[str] = mapped_column(String(64), nullable=False)
    author_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)


class IncidentHistoryModel(Base, UUIDPrimaryKeyMixin):
    """Immutable state transition history for an incident."""

    __tablename__ = "incident_history"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_status: Mapped[str] = mapped_column(String(32), nullable=False)
    changed_by: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
