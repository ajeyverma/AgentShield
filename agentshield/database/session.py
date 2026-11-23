"""
AgentShield AI — Database Configuration and Session Management.

Supports PostgreSQL (production) and SQLite (local development).
The active database URL is determined by AgentShieldSettings.effective_database_url.
"""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.core.config import settings
from agentshield.database.base import Base

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _build_engine_kwargs() -> dict:
    """Return engine creation kwargs appropriate for the configured database."""
    db_url = settings.effective_database_url

    kwargs: dict = {
        "echo": settings.is_development and settings.log_level == "DEBUG",
    }

    if db_url.startswith("postgresql"):
        kwargs["pool_size"] = 10
        kwargs["max_overflow"] = 20
        kwargs["pool_pre_ping"] = True

    elif db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}

    return kwargs


engine = create_async_engine(settings.effective_database_url, **_build_engine_kwargs())

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def get_async_session() -> AsyncSession:  # type: ignore[return]
    """FastAPI dependency yielding a database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Initialization helper (called at backend startup)
# ---------------------------------------------------------------------------


async def initialize_database() -> None:
    """Create all tables that do not yet exist (e.g. for development/tests)."""
    # Import all models so that Base.metadata has full registry
    import agentshield.database.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info(
        "Database initialized",
        extra={"url": _redact_credentials(settings.effective_database_url)},
    )


def _redact_credentials(url: str) -> str:
    """Remove password from a database URL for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(url)
        if parsed.password:
            netloc = parsed.netloc.replace(f":{parsed.password}@", ":***@")
            return urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        pass
    return url
