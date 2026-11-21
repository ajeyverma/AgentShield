"""
AgentShield AI — FastAPI Backend Application.

Entry point for the AgentShield security backend.  This module creates and
configures the FastAPI application instance.

The backend operates independently of the desktop application.  Closing or
restarting the desktop UI does not affect the backend process.

Start the server:
    uvicorn apps.api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentshield.core.config import settings
from agentshield.core.logging import configure_logging
from apps.api.routes import health

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

    # Phase 2+: Initialize database, start background tasks, etc.
    # For Phase 1, the backend starts with no persistent state dependencies.

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
            "Provides security evaluation, policy enforcement, and audit logging "
            "for AI agent tool interactions."
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

    # Phase 2+ routers will be added here:
    # app.include_router(auth.router, prefix=settings.api_prefix)
    # app.include_router(agents.router, prefix=settings.api_prefix)
    # app.include_router(evaluate.router, prefix=settings.api_prefix)
    # app.include_router(approvals.router, prefix=settings.api_prefix)
    # app.include_router(audit.router, prefix=settings.api_prefix)

    return app


app = create_app()
