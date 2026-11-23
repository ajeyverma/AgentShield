"""
AgentShield AI — Database Backup Tool.

Creates timestamped, checksummed database backups for PostgreSQL and SQLite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from agentshield.core.config import settings


def compute_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def backup_sqlite(sqlite_url: str, output_dir: Path) -> tuple[Path, dict]:
    # Extract file path from sqlite+aiosqlite:///path
    db_file_str = sqlite_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
    db_path = Path(db_file_str).resolve()
    if not db_path.exists():
        raise FileNotFoundError(f"SQLite database file not found at: {db_path}")

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    backup_file = output_dir / f"agentshield_backup_{timestamp}.db"

    print(f"Copying SQLite database from {db_path} to {backup_file}...")
    shutil.copy2(db_path, backup_file)

    checksum = compute_sha256(backup_file)
    metadata = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "database_type": "sqlite",
        "original_file": str(db_path),
        "backup_file": backup_file.name,
        "sha256": checksum,
        "size_bytes": backup_file.stat().st_size,
    }
    return backup_file, metadata


def backup_postgres(db_url: str, output_dir: Path) -> tuple[Path, dict]:
    # DSN format: postgresql+asyncpg://user:pass@host:port/dbname
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    backup_file = output_dir / f"agentshield_pgbackup_{timestamp}.dump"

    # Normalize url for pg_dump
    pg_dsn = db_url.replace("postgresql+asyncpg://", "postgresql://")

    print(f"Executing pg_dump to {backup_file}...")
    cmd = ["pg_dump", "-Fc", "--no-owner", "--no-acl", "-d", pg_dsn, "-f", str(backup_file)]
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("Error: pg_dump utility not found in system PATH!")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error executing pg_dump: {e}")
        sys.exit(e.returncode)

    checksum = compute_sha256(backup_file)
    metadata = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "database_type": "postgresql",
        "backup_file": backup_file.name,
        "sha256": checksum,
        "size_bytes": backup_file.stat().st_size,
    }
    return backup_file, metadata


def main():
    parser = argparse.ArgumentParser(description="AgentShield Database Backup Utility")
    parser.add_argument("--output-dir", default="backups", help="Directory where backups are stored")
    args = parser.parse_args()

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    db_url = settings.effective_database_url
    print(f"Initiating AgentShield backup (database URL: {db_url.split('@')[-1] if '@' in db_url else db_url})...")

    if "sqlite" in db_url.lower():
        backup_file, meta = backup_sqlite(db_url, out_dir)
    else:
        backup_file, meta = backup_postgres(db_url, out_dir)

    meta_file = backup_file.with_suffix(".json")
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print("\n" + "=" * 60)
    print(f"SUCCESS: Database backup created at: {backup_file}")
    print(f"Metadata file: {meta_file}")
    print(f"SHA-256: {meta['sha256']}")
    print(f"Size: {meta['size_bytes']} bytes")
    print("=" * 60)


if __name__ == "__main__":
    main()
