"""
AgentShield AI — Multi-Agent Identity & Provenance (Phase 9).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from pydantic import BaseModel, Field

from agentshield.contracts.enums import IntegrationType


class AgentIdentity(BaseModel):
    """Tracks authenticated identity and lineage of an AI agent across framework executions."""

    agent_id: str = Field(..., description="Unique agent identifier.")
    agent_name: str = Field(..., description="Human-readable agent name.")
    framework: IntegrationType = Field(..., description="Framework type.")
    tenant_id: str = Field(..., description="Tenant ID to which this agent belongs.")
    session_id: str | None = Field(default=None, description="Current session identifier.")
    parent_agent_id: str | None = Field(
        default=None,
        description="Identifier of parent agent if this agent was spawned in a hierarchy / delegation.",
    )
    task_id: str | None = Field(default=None, description="Task or workflow graph correlation ID.")
    allowed_tools: list[str] = Field(default_factory=list, description="Tool names authorized for this agent.")
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def originating_agent_id(self) -> str | None:
        """Alias for root or parent agent ID in delegation chains."""
        return self.parent_agent_id

    def derive_delegated_identity(
        self,
        delegated_name: str,
        delegated_agent_id: str | None = None,
        tool_scopes: list[str] | None = None,
    ) -> AgentIdentity:
        """
        Derive identity for a delegated/child agent.
        Does NOT automatically inherit all parent tools — requires explicit or intersected tool scopes.
        """
        # Scopes must be a subset of parent's allowed tools
        parent_tools = set(self.allowed_tools)
        if tool_scopes is not None:
            granted_tools = list(set(tool_scopes).intersection(parent_tools))
        else:
            granted_tools = list(parent_tools)

        child_id = delegated_agent_id or f"del-{uuid.uuid4().hex[:8]}"
        return AgentIdentity(
            agent_id=child_id,
            agent_name=delegated_name,
            framework=self.framework,
            tenant_id=self.tenant_id,
            session_id=self.session_id,
            parent_agent_id=self.agent_id,
            task_id=self.task_id,
            allowed_tools=granted_tools,
            is_active=True,
            created_at=datetime.now(UTC),
        )
