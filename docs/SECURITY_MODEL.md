# AgentShield AI — Security Model

---

## Core Security Principles

### 1. Never Trust the Agent

AI agents are considered untrusted clients. Any identity information supplied by an agent (tool name, arguments, claimed tenant, claimed agent ID) is treated as **untrusted input**.

Identity fields (`tenant_id`, `agent_id`, `user_id`, `session_id`) are always derived from authenticated server-side context — never from the agent request payload.

### 2. Fail Closed

If the AgentShield backend is unreachable or returns an error, the integration layer **must** treat the situation as an implicit **BLOCK**. Tool execution is never permitted on backend failure. This is the fail-closed design.

### 3. Desktop ≠ Enforcement

The desktop application is a management and monitoring interface only. It never contains policy evaluation logic and is never the sole enforcement point. Closing the desktop app does not weaken security.

### 4. No Forged ALLOW Decisions

The Execution Gateway validates a backend-issued authorization token (the `decision_id` from an ALLOW SecurityDecision) before invoking any tool. A client cannot forge an ALLOW decision to bypass evaluation.

### 5. Tenant Isolation

Every piece of data is scoped by `tenant_id`. The repository layer filters every query on `tenant_id` to prevent cross-tenant data access. [Implemented in Phase 2+]

### 6. Least Privilege

Each component has access only to what it needs. The integration layer cannot read the policy database. The desktop app cannot directly invoke the execution gateway.

### 7. Secrets Never in Code

No passwords, API keys, or tokens are stored in source code. All secrets come from environment variables. The `.env` file is excluded from version control by `.gitignore`.

### 8. Audit Minimizes Sensitive Data

Audit log entries record action metadata (tool name, category, decision, risk score) but are designed to avoid logging raw argument values that may contain sensitive data. [Design enforced in Phase 2+]

---

## Identity and Authentication Model

### Connector Authentication

Integration adapters authenticate to the backend using a connector API key (issued at registration time). The backend resolves `tenant_id` and `agent_id` from this credential — the adapter does not supply these values.

### Desktop Authentication

Desktop application users authenticate with username/password or SSO (Phase 2+). JWT access tokens are used for all subsequent API calls.

### Token Signing

JWTs are signed using the `AGENTSHIELD_SECRET_KEY`. This key must be generated securely and rotated periodically in production.

---

## Threat Model Boundaries

| Threat | Mitigation |
|--------|-----------|
| Agent tries to claim false identity | Identity derived server-side from credentials |
| Agent supplies malicious arguments | Arguments size-limited; validated before execution |
| Client forges an ALLOW decision | Execution gateway requires backend-issued token |
| Backend unreachable | Integration enforces BLOCK by default |
| Cross-tenant data access | All queries filtered by tenant_id at repository layer |
| Secret exposure | No secrets in code; .env excluded from git |
| Oversized payload DoS | Arguments limited to 65 536 bytes per request |
| Audit tampering | [Phase 2+] Audit records are append-only |

---

## What Is NOT Implemented in Phase 1

The following security mechanisms are designed but not yet implemented:

- Actual policy evaluation engine
- Risk scoring algorithm
- Threat detection
- Human approval workflows
- Execution authorization token issuance and validation
- JWT authentication
- Tenant data isolation at database level
- Real audit log persistence

These are scheduled for Phase 2–5. The contracts and interfaces defined in Phase 1 are designed to support all of them without breaking changes.
