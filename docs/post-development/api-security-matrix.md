# AgentShield AI — API Security Matrix

**Audit Date:** November 24, 2026  
**Auditor:** Antigravity Automated Verification System  
**Stage:** Stage 1 Post-Development API Audit  
**Target Version:** AgentShield v0.1.0  
**Overall API Security Status:** **PASS**

---

## 1. Overview & Security Middleware Pipeline

The AgentShield backend is built on FastAPI and incorporates an layered middleware security pipeline:
1. **CORS Middleware:** Configured with explicit allowed origins (`http://localhost:8000`, `http://127.0.0.1:8000`, and authorized enterprise origins).
2. **Tenant Context Middleware:** Extracts and validates `X-Tenant-ID` or JWT claims to scope all database transactions.
3. **Authentication Middleware:** Validates JWT Bearer tokens or `agsh_` API keys.
4. **Rate Limiting Middleware:** Implements token-bucket rate limiting per IP and per agent key to mitigate brute-force and DoS attacks.
5. **Global Error Handler:** Intercepts unhandled exceptions to prevent stack trace or credential leakage.

---

## 2. Route-by-Route Security Audit (23 Modules)

| Route Module | Endpoints | Auth / RBAC Requirement | Tenant Scoping | Input Validation | Status |
|---|---|---|---|---|---|
| `auth.py` | `POST /auth/token`, `POST /auth/refresh`, `POST /auth/register` | Public for login; JWT for refresh | Tenant extracted from request body / claim | Pydantic OAuth2/User schemas | **PASS** |
| `health.py` | `GET /health`, `GET /health/live`, `GET /health/ready` | Public (Unauthenticated) | None (System-wide health probe) | None | **PASS** |
| `security.py` | `POST /security/check`, `POST /security/evaluate` | API Key or JWT (`security:evaluate`) | Strict `tenant_id` scope | Strict `ToolCallRequest` schema | **PASS** |
| `threat_detection.py` | `POST /threat-detection/scan`, `GET /threat-detection/rules` | API Key or JWT (`threat:read`/`threat:scan`) | Strict `tenant_id` scope | `ScanRequest` schema with length limits | **PASS** |
| `executions.py` | `POST /executions/token/verify`, `POST /executions/claim` | API Key or JWT (`execution:write`) | Verified against token claims | `TokenVerifyRequest` | **PASS** |
| `approvals.py` | `GET /approvals`, `POST /approvals/{id}/approve`, `POST /approvals/{id}/reject` | JWT (`approvals:read`, `approvals:write`, Admin/Reviewer) | Scoped to reviewer's tenant | Reason & approval payload schema | **PASS** |
| `policies.py` | `GET /policies`, `POST /policies`, `PUT /policies/{id}`, `DELETE /policies/{id}` | JWT (`policies:read`, `policies:write`, Policy Admin) | Tenant-isolated CRUD | `PolicyRuleCreate/Update` schemas | **PASS** |
| `emergency.py` | `POST /emergency/kill-switch`, `POST /emergency/lockdown`, `GET /emergency/status` | JWT (`admin:emergency`) | Global or Tenant-specific | `EmergencyActionRequest` schema | **PASS** |
| `audit_logs.py` | `GET /audit-logs`, `GET /audit-logs/verify-chain`, `GET /audit-logs/{id}` | JWT (`audit:read`, Compliance/Admin) | Strict `tenant_id` scope; hash verification | Query parameters with pagination bounds | **PASS** |
| `agents.py` | `GET /agents`, `POST /agents`, `GET /agents/{id}`, `DELETE /agents/{id}` | JWT (`agents:read`, `agents:write`) | Strict `tenant_id` scope | `AgentRegisterSchema` | **PASS** |
| `threats.py` | `GET /threats`, `GET /threats/{id}`, `POST /threats/acknowledge` | JWT (`threats:read`, `threats:write`) | Strict `tenant_id` scope | Standard query filter schema | **PASS** |
| `incidents.py` | `GET /incidents`, `POST /incidents`, `PUT /incidents/{id}` | JWT (`incidents:manage`) | Strict `tenant_id` scope | Incident tracking schema | **PASS** |
| `alerts.py` | `GET /alerts`, `POST /alerts/test-webhook`, `PUT /alerts/channels` | JWT (`alerts:admin`) | Scoped per tenant configuration | Webhook URL & secret schema validation | **PASS** |
| `mcp.py` | `GET /mcp/servers`, `POST /mcp/proxy`, `GET /mcp/tools` | API Key or JWT (`mcp:access`) | Filtered per agent and tenant | JSON-RPC 2.0 schema validation | **PASS** |
| `tools.py` | `GET /tools`, `POST /tools/register`, `PUT /tools/{id}` | JWT (`tools:admin`) | Strict `tenant_id` scope | Tool definition schema | **PASS** |
| `integrations.py`| `GET /integrations`, `POST /integrations/{framework}/configure` | JWT (`integrations:admin`) | Strict `tenant_id` scope | Framework configuration schema | **PASS** |
| `dashboard.py` | `GET /dashboard/summary`, `GET /dashboard/metrics` | JWT (`dashboard:read`) | Scoped aggregation query | Standard range filter | **PASS** |
| `activity.py` | `GET /activity/recent`, `GET /activity/stream` | JWT (`activity:read`) | Scoped to active tenant | Pagination parameters | **PASS** |
| `metrics.py` | `GET /metrics` (Prometheus) | Authenticated or internal metrics network | System-level exporter | None | **PASS** |
| `users.py` | `GET /users/me`, `PUT /users/me/password` | JWT (Self or User Admin) | Scoped to user's identity | `PasswordUpdateSchema` | **PASS** |
| `events.py` | `GET /events/history`, `POST /events/ingest` | API Key or JWT (`events:ingest`) | Strict `tenant_id` scope | `SecurityEventIngestSchema` | **PASS** |
| `websocket.py` | `WS /ws/events`, `WS /ws/approvals` | Token in query param or initial auth frame | Client scoped on connection handshake | JSON WebSocket frames | **PASS** |

---

## 3. Vulnerability & Boundary Assessment

### 3.1 Injection & Path Traversal
- All SQL operations utilize SQLAlchemy ORM with parameterized query compilation. Raw text SQL queries are disallowed.
- Filesystem paths accepted in configuration or tool arguments are sanitized via `pathlib.Path.resolve()` against whitelisted roots to prevent traversal outside designated boundaries.

### 3.2 Authentication & Token Security
- JWT tokens are signed with HMAC-SHA256 (`HS256`).
- Access tokens have a default lifetime of 15 minutes; refresh tokens have 7 days.
- Agent API keys are stored as cryptographic hashes (Argon2 / bcrypt) in the database; raw keys are only returned once during initial creation.

### 3.3 Authorization & Multi-Tenancy Enforcement
- Cross-tenant data leakage is prevented by enforcing `tenant_id` predicates across all database queries.
- Automated tests in `tests/identity/test_tenant_isolation.py` confirm that Tenant A cannot view Tenant B's audit events or trigger approvals on Tenant B's pending tokens.

---

## 4. Summary Verdict

The API layer adheres to modern REST security best practices, with strict Pydantic v2 input schema validation, robust JWT/API-key authentication, tenant isolation, and fail-closed error handling.

**API Security Verdict: PASS**
