"""
AgentShield AI — Activity Event Database Model.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class ActivityEvent(Base, UUIDPrimaryKeyMixin):
    """Recorded AI agent tool interaction event."""

    __tablename__ = "activity_events"

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
    tool_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    operation: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        default="ALLOW",
        nullable=False,
    )
    risk_level: Mapped[str] = mapped_column(
        String(32),
        default="NONE",
        nullable=False,
    )
    execution_status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        nullable=False,
    )
    arguments_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_activity_user_created", "user_id", "created_at"),
    )
