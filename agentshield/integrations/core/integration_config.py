"""
AgentShield AI — Shared Integration Configuration (Phase 9).
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class AgentShieldIntegrationConfig(BaseModel):
    """Universal configuration for connecting an AI agent framework to AgentShield."""

    backend_url: str = Field(
        default="http://localhost:8000",
        description="Base URL of the AgentShield backend service.",
    )
    api_prefix: str = Field(
        default="/api/v1",
        description="API prefix for AgentShield REST endpoints.",
    )
    agent_id: str = Field(
        ...,
        description="Unique identifier assigned to the agent connector during registration.",
    )
    agent_credential: str = Field(
        ...,
        description="Secret credential token issued by AgentShield for authenticating this agent.",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Tenant identifier for multi-tenant isolation.",
    )
    allowed_tools: list[str] = Field(
        default_factory=lambda: ["calculator", "sandbox_fs", "mock_email", "mock_http"],
        description="Explicit allowlist of permitted tool names. Tools outside this list are rejected.",
    )
    fail_closed: bool = Field(
        default=True,
        description="When True, unreachable backend or evaluation failure results in an immediate BLOCK.",
    )
    timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="HTTP request timeout in seconds.",
    )
    session_id: str | None = Field(
        default=None,
        description="Optional session correlation identifier.",
    )
    custom_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional HTTP headers sent with each gateway request.",
    )
