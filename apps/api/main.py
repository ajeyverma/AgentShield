"""
AgentShield AI — FastAPI Backend Application.

Entry point for the AgentShield security backend.
Operates independently of the desktop application.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentshield.core.config import settings
from agentshield.core.logging import configure_logging
from agentshield.database.session import initialize_database
from apps.api.routes import (
    activity,
    agents,
    approvals,
    audit_logs,
    auth,
    dashboard,
    executions,
    health,
    integrations,
    policies,
    security,
    threat_detection,
    threats,
    tools,
    users,
    websocket,
)

# Configure logging before anything else
configure_logging(level=settings.log_level, fmt=settings.log_format)

logger = logging.getLogger("agentshield.api")


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage startup and shutdown tasks for the FastAPI application."""
    logger.info(
        "AgentShield API starting up",
        extra={
            "version": settings.app_version,
            "env": settings.env.value,
            "api_prefix": settings.api_prefix,
        },
    )

    # Initialize database tables if they do not yet exist
    try:
        await initialize_database()
    except Exception as exc:
        logger.error("Failed to initialize database on startup: %s", exc)

    yield  # Application is running

    logger.info("AgentShield API shutting down.")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application instance."""
    app = FastAPI(
        title=settings.app_name,
        description=(
            "AgentShield AI — Universal Runtime Security Gateway for AI Agents. "
            "Provides identity, security monitoring, policy management, and audit logging."
        ),
        version=settings.app_version,
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        openapi_url=f"{settings.api_prefix}/openapi.json",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(auth.router, prefix=settings.api_prefix)
    app.include_router(users.router, prefix=settings.api_prefix)
    app.include_router(agents.router, prefix=settings.api_prefix)
    app.include_router(dashboard.router, prefix=settings.api_prefix)
    app.include_router(activity.router, prefix=settings.api_prefix)
    app.include_router(threats.router, prefix=settings.api_prefix)
    app.include_router(threat_detection.router, prefix=settings.api_prefix)
    app.include_router(executions.router, prefix=settings.api_prefix)
    app.include_router(tools.router, prefix=settings.api_prefix)
    app.include_router(approvals.router, prefix=settings.api_prefix)
    app.include_router(policies.router, prefix=settings.api_prefix)
    app.include_router(security.router, prefix=settings.api_prefix)
    app.include_router(audit_logs.router, prefix=settings.api_prefix)
    app.include_router(integrations.router, prefix=settings.api_prefix)
    app.include_router(websocket.router, prefix=settings.api_prefix)

    return app


app = create_app()
