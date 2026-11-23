"""
AgentShield AI — Database Restore Tool.

Restores PostgreSQL and SQLite databases from verified backups with checksum validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from agentshield.core.config import settings


def compute_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def restore_sqlite(backup_file: Path, target_url: str):
    target_str = target_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
    target_path = Path(target_str).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Restoring SQLite database to: {target_path}...")
    shutil.copy2(backup_file, target_path)
    print("✓ SQLite database successfully restored.")


def restore_postgres(backup_file: Path, target_url: str):
    pg_dsn = target_url.replace("postgresql+asyncpg://", "postgresql://")
    print(f"Restoring PostgreSQL database using pg_restore...")
    cmd = ["pg_restore", "--clean", "--if-exists", "--no-owner", "-d", pg_dsn, str(backup_file)]
    try:
        subprocess.run(cmd, check=True)
        print("✓ PostgreSQL database successfully restored.")
    except FileNotFoundError:
        print("Error: pg_restore utility not found in PATH!")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error during pg_restore: {e}")
        sys.exit(e.returncode)


def main():
    parser = argparse.ArgumentParser(description="AgentShield Database Restore Utility")
    parser.add_argument("backup_file", help="Path to database backup file (.db or .dump)")
    parser.add_argument("--force", action="store_true", help="Bypass user confirmation prompt")
    args = parser.parse_args()

    backup_path = Path(args.backup_file).resolve()
    if not backup_path.exists():
        print(f"Error: Backup file {backup_path} does not exist!")
        sys.exit(1)

    # Verify checksum if metadata JSON is available
    meta_path = backup_path.with_suffix(".json")
    if meta_path.exists():
        print(f"Verifying backup integrity via metadata: {meta_path}...")
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        expected_sha = meta.get("sha256")
        actual_sha = compute_sha256(backup_path)
        if expected_sha and actual_sha != expected_sha:
            print(f"CRITICAL ERROR: Backup checksum mismatch!\nExpected: {expected_sha}\nActual:   {actual_sha}")
            sys.exit(1)
        print("✓ Backup integrity verified (SHA-256 matches).")

    if not args.force:
        print("\nWARNING: Restoring will overwrite the current active database!")
        confirm = input("Type 'RESTORE' to confirm: ")
        if confirm != "RESTORE":
            print("Restore aborted by user.")
            sys.exit(0)

    db_url = settings.effective_database_url
    if "sqlite" in db_url.lower():
        restore_sqlite(backup_path, db_url)
    else:
        restore_postgres(backup_path, db_url)

    print("Database restore completed successfully.")


if __name__ == "__main__":
    main()
