# AgentShield AI — Local Deployment Guide

This guide covers setting up and running AgentShield AI entirely on a single developer workstation or isolated testing machine.

---

## 1. Architecture of Local Deployment

In a local deployment:
- **Backend API**: Runs locally on `http://127.0.0.1:8000`.
- **Database**: Embedded SQLite (`sqlite+aiosqlite:///./agentshield_dev.db`).
- **Desktop UI**: PySide6 client running on the same host, connecting directly to `127.0.0.1:8000`.
- **AI Agents**: Running locally in Python, intercepting tool executions via localhost gateway calls.

---

## 2. Configuration Setup

Verify that `.env` is populated with local settings:

```ini
AGENTSHIELD_ENV=LOCAL
AGENTSHIELD_HOST=127.0.0.1
AGENTSHIELD_PORT=8000
AGENTSHIELD_DATABASE_URL=sqlite+aiosqlite:///./agentshield_dev.db
AGENTSHIELD_DEBUG=true
AGENTSHIELD_JWT_SECRET=local-development-secret-key-32-chars-minimum!
AGENTSHIELD_RATE_LIMIT_PER_MINUTE=120
```

Validate the configuration:
```bash
python scripts/validate_config.py --env local
```

---

## 3. Database Initialization

Run the automated migration tool:
```bash
python scripts/db_init.py
```
This applies all Alembic revisions up to `head`. You can verify current status with:
```bash
python scripts/db_init.py --status
```

---

## 4. Running the Backend Service

You can run the backend directly using Uvicorn or manage it with the Service Manager:

### Method A: Foreground Uvicorn
```bash
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000 --reload
```

### Method B: Background Service Manager
```bash
# Start backend in background
python scripts/service_manager.py start

# Check status
python scripts/service_manager.py status

# Inspect logs
python scripts/service_manager.py logs -n 50

# Stop backend
python scripts/service_manager.py stop
```

---

## 5. Launching the Desktop UI

With the backend running, launch the management console:
```bash
python apps/desktop/main.py
```

- If this is a fresh setup, the **First-Run Wizard** will appear to verify connection and initialize your credentials.
- The UI will establish a persistent WebSocket connection to `ws://127.0.0.1:8000/api/v1/ws/live` to display live alerts, approvals, and metrics.
