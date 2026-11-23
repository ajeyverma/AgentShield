"""
AgentShield AI — Audit Checkpoint Database Model (Phase 11).
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Boolean, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class AuditCheckpointModel(Base, UUIDPrimaryKeyMixin):
    """Periodic cryptographic checkpoint anchoring the tamper-evident audit hash chain."""

    __tablename__ = "audit_checkpoints"

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    start_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    end_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_checkpoint_tenant_seq", "tenant_id", "start_sequence", "end_sequence"),
    )
