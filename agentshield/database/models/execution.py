"""
AgentShield AI — Tool Execution Database Model (Phase 6).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, UUIDPrimaryKeyMixin, utc_now


class ToolExecutionModel(Base, UUIDPrimaryKeyMixin):
    """Persisted audit and lifecycle state of a tool execution in the Controlled Gateway."""

    __tablename__ = "tool_executions"

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
        String(64),
        index=True,
        nullable=False,
    )
    action_name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    canonical_argument_hash: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    arguments_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
        nullable=True,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
        default="BLOCK",
    )
    decision_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
        default="RECEIVED",
    )
    approval_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    grant_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    result_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    error_code: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    duration_ms: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_exec_user_created", "user_id", "created_at"),
        Index("ix_exec_user_tool", "user_id", "tool_name"),
        Index("ix_exec_user_status", "user_id", "status"),
        Index("ix_exec_idempotency", "user_id", "idempotency_key"),
    )
