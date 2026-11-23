"""
AgentShield AI — MCP Gateway Database Models (Phase 8).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentshield.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class MCPServerModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Registered upstream external MCP server."""

    __tablename__ = "mcp_servers"

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    server_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    server_description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    transport_type: Mapped[str] = mapped_column(
        String(32),
        default="stdio",
        nullable=False,
    )  # "stdio", "streamable_http", "sse"
    endpoint_or_command: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )  # URL or command executable path
    args_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )  # JSON-serialized arguments list for stdio
    env_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )  # JSON-serialized environment variables (redacted/safe)
    protocol_version: Mapped[str] = mapped_column(
        String(32),
        default="2024-11-05",
        nullable=False,
    )
    capabilities_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )  # Discovered tools/resources/prompts metadata
    connection_status: Mapped[str] = mapped_column(
        String(32),
        default="disconnected",
        nullable=False,
    )  # "connected", "disconnected", "error", "pending"
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    trust_classification: Mapped[str] = mapped_column(
        String(32),
        default="untrusted",
        nullable=False,
    )  # "untrusted", "internal", "verified"
    last_connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    __table_args__ = (
        Index("ix_mcp_server_user_name", "user_id", "server_name", unique=True),
        Index("ix_mcp_server_user_status", "user_id", "is_enabled"),
    )


class MCPSessionModel(Base, UUIDPrimaryKeyMixin):
    """Active or historical MCP client-gateway session."""

    __tablename__ = "mcp_sessions"

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    server_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("mcp_servers.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    client_id: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )  # Agent ID or client identity
    session_token: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False,
    )
    transport_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="active",
        nullable=False,
    )  # "active", "closed", "expired"
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_mcp_session_user_status", "user_id", "status"),
    )


class MCPActivityModel(Base, UUIDPrimaryKeyMixin):
    """Audit log of intercepted MCP operations (tools/call, resources/read, prompts/get)."""

    __tablename__ = "mcp_activities"

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    server_id: Mapped[str] = mapped_column(
        String(36),
        index=True,
        nullable=False,
    )
    session_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    client_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    operation_type: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )  # "tools/list", "tools/call", "resources/read", etc.
    target_name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )  # Tool name, resource URI, prompt name
    decision: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
    )  # "ALLOW", "BLOCK", "ASK_HUMAN"
    decision_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    approval_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )  # "completed", "blocked", "pending_approval", "failed"
    request_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )  # Redacted JSON arguments/params
    response_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )  # Redacted output summary
    redaction_applied: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    threat_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    duration_ms: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_mcp_act_user_created", "user_id", "created_at"),
        Index("ix_mcp_act_server_op", "server_id", "operation_type"),
    )
