"""
AgentShield AI — Database Initialization & Migration Tool.

Verifies database connectivity, executes Alembic migrations up to head,
and verifies schema readiness.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from agentshield.core.config import settings


async def check_connection(db_url: str) -> bool:
    print(f"Connecting to database: {db_url.split('@')[-1] if '@' in db_url else db_url}...")
    try:
        engine = create_async_engine(db_url, echo=False)
        async with engine.connect() as conn:
            res = await conn.execute(text("SELECT 1"))
            assert res.scalar() == 1
        await engine.dispose()
        print("✓ Database connection successful.")
        return True
    except Exception as exc:
        print(f"✗ Failed to connect to database: {exc}")
        return False


def run_migrations(alembic_cfg_path: Path):
    print("Running Alembic migrations to head...")
    cfg = Config(str(alembic_cfg_path))
    try:
        command.upgrade(cfg, "head")
        print("✓ Database migrations applied successfully to head.")
    except Exception as exc:
        print(f"✗ Migration failure: {exc}")
        sys.exit(1)


def show_migration_status(alembic_cfg_path: Path):
    cfg = Config(str(alembic_cfg_path))
    print("Checking current migration status...")
    command.current(cfg, verbose=True)


def main():
    parser = argparse.ArgumentParser(description="AgentShield Database Provisioning & Migration Utility")
    parser.add_argument("--status", action="store_true", help="Show current migration status without applying")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    alembic_ini = root / "alembic.ini"
    if not alembic_ini.exists():
        print(f"Error: Could not locate alembic.ini at {alembic_ini}")
        sys.exit(1)

    db_url = settings.effective_database_url

    if args.status:
        show_migration_status(alembic_ini)
        return

    # 1. Connection check
    is_ok = asyncio.run(check_connection(db_url))
    if not is_ok:
        sys.exit(1)

    # 2. Run migrations
    run_migrations(alembic_ini)

    # 3. Print status
    show_migration_status(alembic_ini)


if __name__ == "__main__":
    main()
