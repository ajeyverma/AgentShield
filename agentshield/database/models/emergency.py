"""
AgentShield AI — Emergency Controls Database Model (Phase 10).
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class EmergencyControlModel(Base, UUIDPrimaryKeyMixin):
    """Emergency intervention record to disable agents, tools, MCP servers, or activate lockdown."""

    __tablename__ = "emergency_controls"

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    control_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    target_identifier: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    activated_by: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
    )
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    revoked_by: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revocation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    __table_args__ = (
        Index("ix_emergency_user_active", "user_id", "is_active"),
        Index("ix_emergency_type_target", "control_type", "target_identifier", "is_active"),
    )
