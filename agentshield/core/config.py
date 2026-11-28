"""
AgentShield AI — Centralized Application Configuration.

Configuration is loaded from environment variables (and an optional .env
file) using pydantic-settings.  No secrets or deployment-specific values
are hard-coded here.

Two deployment modes are supported:

    LOCAL  — Backend and desktop on the same machine or LAN.
             SQLite is used by default for the database.
    REMOTE — Backend on a remote server; desktop connects via HTTPS.
             PostgreSQL is required.

Usage
─────
    from agentshield.core.config import settings

    db_url = settings.effective_database_url
    backend = settings.backend_url
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agentshield.contracts.enums import DeploymentMode


class AgentShieldSettings(BaseSettings):
    """All runtime configuration for the AgentShield platform.

    Values are read from environment variables prefixed with AGENTSHIELD_.
    A .env file in the working directory is loaded automatically.
    """

    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Environment / deployment
    # ------------------------------------------------------------------

    env: DeploymentMode = Field(
        default=DeploymentMode.LOCAL,
        description="Deployment mode: LOCAL or REMOTE.",
    )

    @field_validator("env", mode="before")
    @classmethod
    def normalize_env(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.upper()
        return v

    # ------------------------------------------------------------------
    # Backend / API
    # ------------------------------------------------------------------

    backend_url: str = Field(
        default="http://localhost:8000",
        description=(
            "URL the desktop application and integrations use to reach the backend. "
            "Change to an HTTPS URL for REMOTE deployments."
        ),
    )

    api_prefix: str = Field(
        default="/api/v1",
        description="URL prefix for all versioned API routes.",
    )

    host: str = Field(
        default="0.0.0.0",
        description="Host address the backend server listens on.",
    )

    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Port the backend server listens on.",
    )

    reload: bool = Field(
        default=False,
        description="Enable uvicorn auto-reload.  MUST be False in production.",
    )

    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        description="Allowed CORS origins for browser-based clients.",
    )

    # ------------------------------------------------------------------
    # Security / authentication
    # ------------------------------------------------------------------

    secret_key: str = Field(
        default="",
        description=(
            "Secret key for signing JWT tokens.  MUST be set via environment variable "
            "in any non-development environment.  Generate with: "
            "python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        ),
    )

    access_token_expire_minutes: int = Field(
        default=60,
        ge=1,
        description="JWT access token lifetime in minutes.",
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    database_url: str | None = Field(
        default=None,
        description=(
            "Primary database DSN (PostgreSQL).  "
            "Format: postgresql+asyncpg://user:password@host:port/dbname"
        ),
    )

    sqlite_url: str = Field(
        default="sqlite+aiosqlite:///./agentshield_dev.db",
        description=(
            "SQLite DSN used as a fallback when DATABASE_URL is not set.  "
            "Acceptable for local development only."
        ),
    )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    log_level: str = Field(
        default="INFO",
        description="Log level: DEBUG | INFO | WARNING | ERROR | CRITICAL.",
    )

    log_format: str = Field(
        default="console",
        description=(
            "Log output format.  "
            "'console' — human-readable coloured output for development. "
            "'json'    — structured JSON output for production / log aggregation."
        ),
    )

    # ------------------------------------------------------------------
    # WhatsApp / Twilio Notifications
    # ------------------------------------------------------------------

    twilio_account_sid: str = Field(
        default="",
        description="Twilio Account SID for WhatsApp alerts.",
    )
    twilio_auth_token: str = Field(
        default="",
        description="Twilio Auth Token for WhatsApp alerts.",
    )
    twilio_whatsapp_from: str = Field(
        default="whatsapp:+14155238886",
        description="Twilio WhatsApp sender phone (e.g. sandbox number).",
    )
    twilio_whatsapp_to: str = Field(
        default="whatsapp:+916393121212",
        description="Recipient phone number for WhatsApp approval alerts.",
    )

    # ------------------------------------------------------------------
    # Version info (read-only)
    # ------------------------------------------------------------------

    app_name: str = Field(default="AgentShield AI", description="Application display name.")
    app_version: str = Field(default="0.1.0", description="Application version string.")

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}. Got '{v}'.")
        return upper

    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        allowed = {"console", "json"}
        lower = v.lower()
        if lower not in allowed:
            raise ValueError(f"log_format must be one of {allowed}. Got '{v}'.")
        return lower

    @model_validator(mode="after")
    def warn_on_missing_secret_key(self) -> "AgentShieldSettings":
        if self.env == DeploymentMode.REMOTE and not self.secret_key:
            raise ValueError(
                "AGENTSHIELD_SECRET_KEY must be set when AGENTSHIELD_ENV=REMOTE. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
            )
        return self

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def effective_database_url(self) -> str:
        """Return the database URL to use, normalizing postgres to asyncpg and falling back safely."""
        import os
        raw = self.database_url or os.getenv("DATABASE_URL") or os.getenv("AGENTSHIELD_DATABASE_URL")
        if raw and raw.strip():
            url = raw.strip()
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql+asyncpg://", 1)
            elif url.startswith("postgresql://") and "+asyncpg" not in url:
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            return url
        return self.sqlite_url

    @property
    def is_development(self) -> bool:
        """True when running in LOCAL mode (suitable for debug features)."""
        return self.env == DeploymentMode.LOCAL


@lru_cache(maxsize=1)
def get_settings() -> AgentShieldSettings:
    """Return the cached singleton settings instance.

    Use this function everywhere instead of constructing AgentShieldSettings
    directly so that the environment is only parsed once.
    """
    return AgentShieldSettings()


# Module-level convenience alias.
settings = get_settings()
