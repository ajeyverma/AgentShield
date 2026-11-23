"""
AgentShield AI — Threat Event Database Model.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ThreatEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Recorded security threat or anomaly."""

    __tablename__ = "threat_events"

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
    threat_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="MEDIUM",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="open",
        nullable=False,
    )

    __table_args__ = (
        Index("ix_threat_user_status", "user_id", "status"),
    )
