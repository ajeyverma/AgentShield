"""
AgentShield AI — Approval Request Database Model.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class ApprovalRequest(Base, UUIDPrimaryKeyMixin):
    """Pending or resolved human approval request."""

    __tablename__ = "approval_requests"

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
    request_id: Mapped[str] = mapped_column(
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
    risk_level: Mapped[str] = mapped_column(
        String(32),
        default="MEDIUM",
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_approval_user_status", "user_id", "status"),
    )
