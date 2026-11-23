# AgentShield AI — Remote Deployment Guide

This guide describes deploying the AgentShield backend as a centralized, hardened security gateway on remote servers or cloud environments (AWS, GCP, Azure, bare metal).

---

## 1. Remote Architecture

In a remote deployment:
- **Centralized Security Backend**: Runs behind an Nginx reverse proxy with TLS 1.3 termination.
- **Database**: Managed PostgreSQL instance (e.g., AWS RDS, Cloud SQL) with connection pooling.
- **Clients**: PySide6 Desktop consoles running on analyst laptops, connecting over HTTPS/WSS.
- **Agents**: AI agents running in cloud pipelines, servers, or edge containers dispatching tool execution requests to the remote gateway.

```
[ AI Agent Cluster ] ──HTTPS──┐
                              │
[ Remote Desktop UI ] ──WSS───┼──▶ [ Nginx Reverse Proxy (TLS 1.3) ]
                              │              │
[ MCP Clients ] ────────HTTPS─┘              ▼
                                  [ AgentShield Backend (FastAPI) ]
                                             │
                                             ▼
                                  [ PostgreSQL Database ]
```

---

## 2. Environment Configuration

Create `/etc/agentshield/.env` based on `.env.production.example`:

```ini
AGENTSHIELD_ENV=REMOTE
AGENTSHIELD_HOST=0.0.0.0
AGENTSHIELD_PORT=8000
AGENTSHIELD_DATABASE_URL=postgresql+asyncpg://agentshield_user:StrongPassword@postgres.internal:5432/agentshield_prod
AGENTSHIELD_DEBUG=false
AGENTSHIELD_JWT_SECRET=GENERATE_HIGH_ENTROPY_KEY_WITH_OPENSSL_RAND_HEX_32
AGENTSHIELD_CORS_ORIGINS=["https://console.agentshield.internal"]
AGENTSHIELD_RATE_LIMIT_PER_MINUTE=600
```

Run pre-flight validation:
```bash
python scripts/validate_config.py --env remote --config /etc/agentshield/.env
```

---

## 3. Docker Compose Production Deployment

The recommended production deployment utilizes Docker:

```bash
# Navigate to deployment directory
cd /opt/agentshield

# Pull or build container
docker compose build

# Start services in detached mode
docker compose up -d

# Verify health status
docker compose ps
```

---

## 4. Nginx Reverse Proxy & TLS Configuration

Deploy `deployment/nginx/agentshield.conf` to `/etc/nginx/sites-available/agentshield.conf`:

Key security features configured in the template:
1. **TLS 1.2 / 1.3** with modern cipher suites.
2. **WebSocket Upgrades** (`/api/v1/ws/`) for real-time telemetry streaming.
3. **Rate Limiting zones** (`api_limit` at 100r/s with burst of 50).
4. **Security Headers**: HSTS, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy.

```bash
ln -s /etc/nginx/sites-available/agentshield.conf /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

---

## 5. Systemd Service Deployment (Bare Metal)

If deploying directly on a Linux virtual machine:

1. Copy service file:
   ```bash
   cp deployment/systemd/agentshield-backend.service /etc/systemd/system/
   ```
2. Create dedicated user and directories:
   ```bash
   useradd -r -s /bin/false agentshield
   mkdir -p /var/log/agentshield
   chown agentshield:agentshield /var/log/agentshield
   ```
3. Enable and start:
   ```bash
   systemctl daemon-reload
   systemctl enable agentshield-backend
   systemctl start agentshield-backend
   ```
