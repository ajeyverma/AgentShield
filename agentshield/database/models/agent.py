"""
AgentShield AI — Agent Database Model.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentshield.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from agentshield.database.models.user import User


class Agent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Registered AI Agent connector."""

    __tablename__ = "agents"

    owner_user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    agent_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    framework: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="custom",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="active",
        nullable=False,
    )
    credential_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationship
    owner: Mapped[User] = relationship("User", back_populates="agents")
