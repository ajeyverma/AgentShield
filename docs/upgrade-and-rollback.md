# AgentShield AI — Upgrade and Rollback Guide

This document details procedures for safely upgrading AgentShield AI releases and rolling back if necessary.

---

## 1. Pre-Upgrade Preparation

Always execute a database backup and record the current release version before upgrading:

```bash
# 1. Create a full database backup
python scripts/backup_db.py

# 2. Check current migration revision
python scripts/db_init.py --status
```

---

## 2. Upgrading the Deployment

### Step 1: Pull New Release
```bash
git pull origin main
# or checkout specific release tag
git checkout tags/v1.1.0
```

### Step 2: Update Python Dependencies
```bash
pip install -r requirements.txt --upgrade
```

### Step 3: Apply Database Migrations
```bash
python scripts/db_init.py
```

### Step 4: Validate Configuration & Health
```bash
python scripts/validate_config.py --env remote
python scripts/service_manager.py restart
curl http://localhost:8000/health
```

---

## 3. Rollback Procedure

If an upgrade fails or introduces regressions:

### Step 1: Stop Backend Service
```bash
python scripts/service_manager.py stop
# or docker compose down
```

### Step 2: Rollback Code Version
```bash
git checkout <previous_commit_or_tag>
```

### Step 3: Restore Database Backup
```bash
python scripts/restore_db.py --file backups/<target_backup>.db --force
```

### Step 4: Restart Service and Verify Integrity
```bash
python scripts/service_manager.py start
curl http://localhost:8000/health
```
