"""
AgentShield AI — Policy & Policy Version Database Models (Phase 10).
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentshield.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class Policy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Security policy configuration with Phase 10 scopes, precedence, and structured conditions."""

    __tablename__ = "policies"

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="general",
    )
    enforcement_mode: Mapped[str] = mapped_column(
        String(32),
        default="enforce",
        nullable=False,
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    rules_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    # Phase 10 Extensions
    priority: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False,
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    agent_scope: Mapped[str] = mapped_column(
        String(255),
        default="*",
        nullable=False,
    )
    integration_scope: Mapped[str] = mapped_column(
        String(64),
        default="*",
        nullable=False,
    )
    tool_scope: Mapped[str] = mapped_column(
        String(128),
        default="*",
        nullable=False,
    )
    action_scope: Mapped[str] = mapped_column(
        String(128),
        default="*",
        nullable=False,
    )
    resource_scope: Mapped[str] = mapped_column(
        String(255),
        default="*",
        nullable=False,
    )
    conditions_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        default="ASK_HUMAN",
        nullable=False,
    )
    approval_requirements_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    created_by: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    updated_by: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_policy_user_category", "user_id", "category"),
        Index("ix_policy_user_priority", "user_id", "priority"),
    )


class PolicyVersion(Base, UUIDPrimaryKeyMixin):
    """Immutable historic version snapshot of a policy."""

    __tablename__ = "policy_versions"

    policy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("policies.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    enforcement_mode: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    agent_scope: Mapped[str] = mapped_column(
        String(255),
        default="*",
        nullable=False,
    )
    integration_scope: Mapped[str] = mapped_column(
        String(64),
        default="*",
        nullable=False,
    )
    tool_scope: Mapped[str] = mapped_column(
        String(128),
        default="*",
        nullable=False,
    )
    action_scope: Mapped[str] = mapped_column(
        String(128),
        default="*",
        nullable=False,
    )
    resource_scope: Mapped[str] = mapped_column(
        String(255),
        default="*",
        nullable=False,
    )
    conditions_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    rules_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    approval_requirements_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    changed_by: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
    )
    change_reason: Mapped[str | None] = mapped_column(
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
        Index("ix_policy_version_lookup", "policy_id", "version"),
    )
