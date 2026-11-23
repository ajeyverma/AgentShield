# AgentShield AI — Configuration Reference

This document provides a comprehensive reference for all configuration options supported by AgentShield AI.

---

## 1. Environment Variables Reference

Configuration values can be provided via environment variables or a `.env` file loaded at startup. All variables use the `AGENTSHIELD_` prefix.

| Variable Name | Type | Default | Description |
|---|---|---|---|
| `AGENTSHIELD_ENV` | String | `LOCAL` | Deployment environment: `LOCAL` or `REMOTE`. |
| `AGENTSHIELD_DEBUG` | Boolean | `false` | Enables debug logging and detailed stack traces. Must be `false` in production. |
| `AGENTSHIELD_HOST` | String | `127.0.0.1` | Network interface to bind backend server. Use `0.0.0.0` in containers. |
| `AGENTSHIELD_PORT` | Integer | `8000` | Port for the backend API server. |
| `AGENTSHIELD_DATABASE_URL` | String | `sqlite+aiosqlite:///./agentshield_dev.db` | Async database connection DSN (PostgreSQL or SQLite). |
| `AGENTSHIELD_JWT_SECRET` | String | Required | Secret key used for signing JWTs and HMAC execution grants. Must be $\ge 32$ characters. |
| `AGENTSHIELD_JWT_ALGORITHM` | String | `HS256` | Cryptographic algorithm for JWTs (`HS256`, `HS384`, `HS512`). |
| `AGENTSHIELD_ACCESS_TOKEN_EXPIRE_MINUTES` | Integer | `60` | Lifespan of operator access tokens. |
| `AGENTSHIELD_CORS_ORIGINS` | JSON List | `["*"]` | Allowed CORS origins for browser/API clients. |
| `AGENTSHIELD_RATE_LIMIT_PER_MINUTE` | Integer | `120` | Maximum requests per minute per IP/client token. |
| `AGENTSHIELD_APPROVAL_TIMEOUT_SECONDS` | Integer | `300` | Timeout before an `ASK_HUMAN` request automatically expires to `BLOCK`. |
| `AGENTSHIELD_MAX_PAYLOAD_SIZE_BYTES` | Integer | `10485760` | Maximum request payload size (10 MB). |

---

## 2. Secrets Management & Entropy Requirements

- In production (`AGENTSHIELD_ENV=REMOTE`), `AGENTSHIELD_JWT_SECRET` must have high entropy.
- You can generate a production-ready secret with OpenSSL:
  ```bash
  openssl rand -hex 32
  ```
- The built-in validator script (`scripts/validate_config.py`) will automatically block startup if weak or default keys are detected in production mode.

---

## 3. Configuration Validation CLI

AgentShield includes a pre-flight validator to test configurations prior to deployment:

```bash
# Validate local environment
python scripts/validate_config.py --env local

# Validate remote production environment
python scripts/validate_config.py --env remote --config /etc/agentshield/.env
```

**Validation Checks Include:**
- Entropy check on `JWT_SECRET`.
- Verification that `DEBUG` is disabled in `REMOTE` mode.
- Verification that production database is PostgreSQL rather than SQLite.
- DSN format and scheme validation (`postgresql+asyncpg://` or `sqlite+aiosqlite://`).
