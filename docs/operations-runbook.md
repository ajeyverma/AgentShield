# AgentShield AI — Operations Runbook

This runbook outlines day-to-day operational procedures, incident response steps, and health verification routines for AgentShield AI operators.

---

## 1. System Health & Monitoring

### Standard Health Endpoint
```bash
GET /health
```
Returns:
```json
{
  "status": "ok",
  "database": "connected",
  "version": "1.0.0",
  "active_tenants": 1
}
```

### Metrics & Telemetry
- Prometheus metrics are exposed at `/metrics` (request counts, latency histograms, risk score distribution, block rates).
- WebSocket connection monitor: Check `/api/v1/ws/live` connection counters.

---

## 2. Emergency Controls & Incident Response

### 2.1 Agent Emergency Lockdown
When an agent exhibits rogue behavior or is suspected of prompt injection:
1. Open Desktop UI -> **Agents** -> Select Agent -> Click **Emergency Lockdown**.
2. Or via API:
   ```bash
   POST /api/v1/agents/{agent_id}/lockdown
   ```
   *Effect*: Instantly revokes all active execution grants and forces all subsequent tool requests to `BLOCK`.

### 2.2 Global System Lockdown
In an active security compromise scenario:
1. Trigger Global Lockdown via Desktop UI top navigation or API:
   ```bash
   POST /api/v1/security/lockdown
   ```
   *Effect*: All tool calls across all tenants are immediately blocked. Only read-only audit inspection is permitted.

---

## 3. Log Rotation & Maintenance

- Log files are managed via Python `RotatingFileHandler` with 50 MB rollover limits and 10 retained backups.
- For Docker/Systemd, journald handles syslog forwarding.
