"""
AgentShield AI — OpenAI Agents SDK Integration Configuration (Phase 7).
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AgentShieldIntegrationConfig(BaseModel):
    """Configuration settings for connecting the OpenAI Agents SDK to AgentShield."""

    backend_url: str = Field(
        default_factory=lambda: os.getenv("AGENTSHIELD_BACKEND_URL", "http://localhost:8000"),
        description="Base URL of the AgentShield FastAPI backend server.",
    )
    api_prefix: str = Field(
        default="/api/v1",
        description="REST API prefix.",
    )
    agent_id: str = Field(
        default_factory=lambda: os.getenv("AGENTSHIELD_AGENT_ID", ""),
        description="Registered Agent ID in AgentShield.",
    )
    agent_credential: str = Field(
        default_factory=lambda: os.getenv("AGENTSHIELD_AGENT_CREDENTIAL", ""),
        description="Agent authentication secret credential (never logged or exposed to model).",
    )
    user_id: str | None = Field(
        default=None,
        description="Optional tenant/user ID. Validated by backend.",
    )
    allowed_tools: list[str] = Field(
        default_factory=lambda: ["calculator", "sandbox_fs", "mock_email", "mock_http"],
        description="Strict allowlist of registered AgentShield tools exposed to the model.",
    )
    timeout_seconds: float = Field(
        default=15.0,
        ge=1.0,
        le=120.0,
        description="HTTP communication timeout in seconds.",
    )
    fail_closed: bool = Field(
        default=True,
        description="Whether to block execution if AgentShield backend is unreachable.",
    )
    model_name: str = Field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        description="OpenAI model identifier to use with the SDK.",
    )
    provider_api_key: str | None = Field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY"),
        description="Model provider API key (used exclusively for LLM queries, never as AgentShield credential).",
    )
    agent_name: str = Field(
        default="AgentShield-Secured Agent",
        description="Display name for the agent.",
    )
    agent_instructions: str = Field(
        default=(
            "You are an AI assistant operating under the AgentShield AI runtime security gateway. "
            "All your tool calls are independently inspected, authorized, and executed by AgentShield. "
            "If an action is blocked or paused for human approval, explain the security outcome politely to the user."
        ),
        description="Base instructions given to the agent.",
    )

    @field_validator("allowed_tools")
    @classmethod
    def validate_allowed_tools(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("allowed_tools cannot be empty. Specify at least one permitted tool.")
        return [t.strip().lower() for t in v]

    def __repr__(self) -> str:
        masked_cred = "***REDACTED***" if self.agent_credential else "None"
        masked_key = "***REDACTED***" if self.provider_api_key else "None"
        return (
            f"AgentShieldIntegrationConfig(backend_url='{self.backend_url}', "
            f"agent_id='{self.agent_id}', agent_credential='{masked_cred}', "
            f"model_name='{self.model_name}', provider_api_key='{masked_key}', "
            f"allowed_tools={self.allowed_tools})"
        )

    def __str__(self) -> str:
        return self.__repr__()
