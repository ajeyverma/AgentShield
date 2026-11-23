"""
AgentShield AI — Threat Finding Database Model (Phase 5).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class ThreatFindingModel(Base, UUIDPrimaryKeyMixin):
    """Persisted threat finding identified by a threat detector."""

    __tablename__ = "threat_findings"

    request_id: Mapped[str] = mapped_column(
        String(36),
        index=True,
        nullable=False,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    agent_id: Mapped[str] = mapped_column(
        String(36),
        index=True,
        nullable=False,
    )
    detector_id: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    threat_type: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
        default="MEDIUM",
    )
    confidence: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="MEDIUM",
    )
    risk_contribution: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )
    evidence_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    affected_resource: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    recommended_action: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
        default="open",
    )
    detector_version: Mapped[str] = mapped_column(
        String(32),
        default="1.0.0",
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_finding_user_created", "user_id", "created_at"),
        Index("ix_finding_user_status", "user_id", "status"),
        Index("ix_finding_user_severity", "user_id", "severity"),
    )
