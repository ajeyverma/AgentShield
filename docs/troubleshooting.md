# AgentShield AI — Troubleshooting Guide

This guide provides troubleshooting steps for common installation, networking, authorization, and runtime issues.

---

## 1. Desktop Application Issues

### Issue: "Disconnected from Backend" / Status Badge Red
- **Symptom**: The top status indicator in the PySide6 UI shows "DISCONNECTED".
- **Resolution**:
  1. Verify the backend process is running:
     ```bash
     python scripts/service_manager.py status
     ```
  2. Check if the port (default `8000`) is accessible:
     ```bash
     curl http://127.0.0.1:8000/health
     ```
  3. Ensure WebSocket connectivity is not blocked by local proxy or firewall (`ws://127.0.0.1:8000/api/v1/ws/live`).

---

## 2. Gateway & Execution Issues

### Issue: Agent Tool Call Fails with `403 Forbidden` / `BLOCK`
- **Symptom**: Agent throws `AgentShieldSecurityException: Tool execution blocked`.
- **Resolution**:
  1. Check the Audit Log in the Desktop UI or query `/api/v1/audit/events`.
  2. Inspect the `block_reasons` field in the response.
  3. Common causes:
     - Tool not registered in the agent's allowlist.
     - Risk score exceeded threshold (e.g., untrusted network target or high-risk command parameter).
     - Matching an explicit `DENY` security policy.

### Issue: Tool Execution Grant Expired
- **Symptom**: Tool adapter reports `Invalid or Expired Execution Grant`.
- **Resolution**:
  - Grants expire 60 seconds after generation. Ensure your agent initiates execution promptly upon receiving the grant.
  - Check clock skew between agent server and AgentShield backend host.

---

## 3. Database & Migrations

### Issue: Migration Revision Conflicts
- **Resolution**:
  1. Inspect status:
     ```bash
     python scripts/db_init.py --status
     ```
  2. If working with SQLite in development, back up and rebuild:
     ```bash
     python scripts/backup_db.py
     python scripts/db_init.py
     ```
