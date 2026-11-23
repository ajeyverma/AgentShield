# AgentShield AI — Backup and Recovery Guide

AgentShield includes automated backup and restore tooling with SHA-256 cryptographic verification to guarantee disaster recovery readiness.

---

## 1. Automated Backup Tool (`scripts/backup_db.py`)

The backup utility exports the active database, creates a metadata manifest, and computes a SHA-256 checksum to prevent undetected backup corruption.

### Performing a Backup
```bash
python scripts/backup_db.py
```

Output:
```
[INFO] Starting database backup...
[INFO] Source Database: sqlite+aiosqlite:///./agentshield_dev.db
[INFO] Backup written to: backups/agentshield_backup_20261123_195710.db
[INFO] SHA-256 Checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
[INFO] Metadata manifest created: backups/agentshield_backup_20261123_195710.db.meta.json
```

---

## 2. Safe Database Restore Tool (`scripts/restore_db.py`)

The restore utility validates the SHA-256 checksum against the manifest before restoring.

### Restoring from Backup
```bash
# Dry-run validation check
python scripts/restore_db.py --file backups/agentshield_backup_20261123_195710.db --dry-run

# Execute restore
python scripts/restore_db.py --file backups/agentshield_backup_20261123_195710.db --force
```

If a backup file has been altered or corrupted, the restore tool terminates immediately and reports a verification failure.
