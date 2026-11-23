"""
AgentShield AI — Identity Schemas.

Pydantic schemas for User and Agent authentication and lifecycle operations.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------------------------------------------------------------------------
# User schemas
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    """Registration request for a new human user."""

    email: EmailStr
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    """User credentials for token issuance."""

    username_or_email: str
    password: str


class UserUpdate(BaseModel):
    """Fields a user can update on their own profile."""

    email: EmailStr | None = None
    username: str | None = Field(default=None, min_length=3, max_length=64)
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserResponse(BaseModel):
    """Public representation of a User. Never contains hashed_password."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    username: str
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime


class TokenResponse(BaseModel):
    """JWT bearer token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


# ---------------------------------------------------------------------------
# Agent schemas
# ---------------------------------------------------------------------------


class AgentCreate(BaseModel):
    """Payload to register a new AI Agent connector."""

    agent_name: str = Field(min_length=2, max_length=128)
    framework: str = Field(default="custom", max_length=64)
    description: str | None = Field(default=None, max_length=500)


class AgentUpdate(BaseModel):
    """Payload to update an existing agent connector."""

    agent_name: str | None = Field(default=None, min_length=2, max_length=128)
    description: str | None = None
    status: str | None = Field(default=None, pattern=r"^(active|idle|deactivated)$")


class AgentResponse(BaseModel):
    """Public representation of an Agent. Never contains credential_hash."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_user_id: str
    agent_name: str
    framework: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime | None


class AgentCreatedResponse(AgentResponse):
    """Returned ONLY upon agent creation or credential rotation."""

    raw_credential: str = Field(
        description="The plaintext agent credential token. Displayed only once."
    )


class AgentAuthenticateRequest(BaseModel):
    """Payload for an agent to authenticate directly."""

    credential: str = Field(min_length=10)


class AgentAuthResponse(BaseModel):
    """Response returned when an agent successfully authenticates."""

    authenticated: bool
    agent: AgentResponse
