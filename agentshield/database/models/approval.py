"""
AgentShield AI — Approval Request & History Database Models (Phase 10).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
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
    # Phase 10 Extended Fields
    execution_id: Mapped[str | None] = mapped_column(
        String(36),
        index=True,
        nullable=True,
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    integration_type: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    resource: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )
    threat_findings_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    policy_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    canonical_argument_hash: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    arguments_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    reviewed_by: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    reviewer_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    review_comment: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    rejection_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
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
        Index("ix_approval_tenant_status", "tenant_id", "status"),
    )


class ApprovalHistory(Base, UUIDPrimaryKeyMixin):
    """Immutable audit trail of state transitions for an approval request."""

    __tablename__ = "approval_history"

    approval_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("approval_requests.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    previous_status: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    new_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    performed_by: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
    )
    performer_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    comment: Mapped[str | None] = mapped_column(
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
        Index("ix_approval_hist_appr_created", "approval_id", "created_at"),
    )
