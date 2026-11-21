"""
AgentShield AI — Health Check Route.

GET /api/v1/health

Returns the current operational status of the AgentShield backend,
including the API version and deployment mode.

This endpoint is intentionally unauthenticated so that:
  - Container orchestrators (Docker, Kubernetes) can probe it.
  - The desktop application can verify backend connectivity before login.
  - Operations teams can confirm the service is running.

It MUST NOT return sensitive configuration values.
"""

from __future__ import annotations

import platform
from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel

from agentshield.core.config import settings

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Response schema for the health check endpoint."""

    status: str
    service: str
    version: str
    environment: str
    api_prefix: str
    timestamp: str
    python_version: str


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Backend health check",
    description=(
        "Returns the operational status of the AgentShield backend. "
        "This endpoint is unauthenticated and safe for use by health-check probes."
    ),
)
async def health_check() -> HealthResponse:
    """Return current service health and version information."""
    return HealthResponse(
        status="healthy",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.env.value,
        api_prefix=settings.api_prefix,
        timestamp=datetime.now(UTC).isoformat(),
        python_version=platform.python_version(),
    )
