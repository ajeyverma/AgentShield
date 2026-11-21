# AgentShield AI — System Architecture

> **Phase 1** — Foundation architecture only. Components marked [Phase N+] are planned but not yet implemented.

---

## 1. System Overview

AgentShield AI enforces security between AI agents and the tools they use. It operates as an independent gateway — no AI agent can bypass or influence its security decisions.

```
USER / ADMIN
    │
    ▼
AGENTSHIELD DESKTOP APPLICATION (PySide6)
    │  Management & monitoring only
    │  Authenticated REST API / WebSocket
    │
    ▼
AGENTSHIELD BACKEND (FastAPI)
    ├── API Layer             — Request routing and validation
    ├── Identity & Tenant     — Agent registration, auth [Phase 2+]
    ├── Security Core         — Policy + risk + threat [Phase 3+]
    ├── Policy Engine         — Rule evaluation [Phase 3+]
    ├── Threat Detection      — Anomaly detection [Phase 3+]
    ├── Risk Engine           — Risk scoring [Phase 3+]
    ├── Approval Management   — Human approval workflows [Phase 4+]
    ├── Execution Gateway     — Authorized tool invocation [Phase 4+]
    └── Audit & Monitoring    — Tamper-evident logs [Phase 2+]
    │
    ▼
AGENTSHIELD INTEGRATION LAYER
    ├── SDK/API Adapters      — Per-framework adapters [Phase 4+]
    ├── MCP Proxy             — MCP transparent proxy [Phase 5+]
    └── Custom Agent Adapter  — Direct SDK integration [Phase 4+]
    │
    ▼
AI AGENTS & CONTROLLED TOOLS
    ├── OpenAI Agents, Claude, LangGraph, CrewAI, Google ADK
    └── Custom Python agents
    │
    ▼
PROTECTED RESOURCES
    └── Files, Email, Browser, Terminal, Databases, External APIs
```

---

## 2. Deployment Modes

### Local Mode (Development / Individual)

- Desktop application and backend run on the same machine or LAN.
- SQLite database (no additional infrastructure required).
- HTTP communication is acceptable on localhost.
- Suitable for: development, testing, single-user deployments.

### Remote Mode (Production / Enterprise)

- Backend runs on a dedicated server or cloud environment.
- Desktop application connects over authenticated HTTPS.
- PostgreSQL as the persistent database.
- Multiple agent connectors can communicate with one centralized backend.
- Configuration changes (backend URL) do not require code changes in the desktop app.

---

## 3. Component Responsibilities

### Desktop Application

- **Management interface only.** Displays security events, policies, agent status, and approval queues.
- **Never enforces security.** Does not contain policy evaluation logic.
- Communicates with the backend through authenticated REST and WebSocket APIs.
- Closing the desktop app does not stop the backend.

### Security Backend

- The **only** security enforcement point in the system.
- Operates independently of the desktop application.
- Accepts action requests from integration adapters.
- Returns SecurityDecision (ALLOW / BLOCK / ASK_HUMAN).
- Records every decision in the audit log.
- Issues cryptographically signed execution authorization tokens.

### Integration Layer

- Intercepts tool calls within AI agent frameworks.
- Maps native tool-call formats to the shared ActionRequest contract.
- Submits requests to the backend for evaluation.
- Obeys the SecurityDecision — it cannot override or modify it.
- Enforces fail-closed behavior when the backend is unreachable.

---

## 4. Security Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| Fail-closed | If the backend is unreachable, default to BLOCK. Never ALLOW on backend failure. |
| No trust in agent identity | tenant_id, agent_id, session_id are always derived server-side, never from agent request payload. |
| Signed execution tokens | Execution gateway validates a backend-issued decision_id before invoking any tool. |
| Backend-independent desktop | Desktop app connects by URL; changing the URL is the only change needed to switch environments. |
| Shared contracts | SDK and MCP integrations use the same ActionRequest / SecurityDecision contracts. |
| Tenant isolation | All data is scoped by tenant_id. Row-level filtering enforced at the repository layer [Phase 2+]. |

---

## 5. Data Flow — Action Evaluation

```
Agent Framework
    │  (native tool call)
    ▼
Integration Adapter
    │  normalize_request() → ActionRequest
    ▼
AgentShield Backend  (POST /api/v1/evaluate)
    │  Validate → Identity → Security Core → Audit log
    ▼
SecurityDecision  (ALLOW | BLOCK | ASK_HUMAN)
    │
    ├── ALLOW     → Execution Gateway (with signed token) → Tool
    ├── BLOCK     → Return error to agent
    └── ASK_HUMAN → Approval workflow → (eventual ALLOW or BLOCK)
```

---

## 6. Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | ≥ 3.11 |
| Backend | FastAPI + uvicorn | ≥ 0.115 |
| Desktop | PySide6 | ≥ 6.7 |
| Validation | Pydantic v2 | ≥ 2.9 |
| ORM | SQLAlchemy (async) | ≥ 2.0 |
| Migrations | Alembic | ≥ 1.13 |
| Database (prod) | PostgreSQL | 16+ |
| Database (dev) | SQLite (aiosqlite) | — |
| Real-time | WebSockets | ≥ 13.0 |
| Testing | Pytest + pytest-asyncio | ≥ 8.0 |
| Containers | Docker + Docker Compose | — |
