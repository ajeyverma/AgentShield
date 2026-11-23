"""
AgentShield AI — Audit Log Database Model.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class AuditLog(Base, UUIDPrimaryKeyMixin):
    """Immutable audit trail record."""

    __tablename__ = "audit_logs"

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    agent_id: Mapped[str | None] = mapped_column(
        String(36),
        index=True,
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    resource_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    resource_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    # Phase 11 Tamper-Evident Hash Chain Fields
    tenant_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    actor_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    action: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    target: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )
    result: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    sequence_number: Mapped[int | None] = mapped_column(
        nullable=True,
        index=True,
    )
    previous_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    current_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    canonical_payload: Mapped[str | None] = mapped_column(
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
        Index("ix_audit_user_created", "user_id", "created_at"),
    )
