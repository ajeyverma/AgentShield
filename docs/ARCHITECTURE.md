# AgentShield AI — System Architecture

## 1. High-Level Overview

AgentShield AI is an independent, universal runtime security platform designed specifically to govern, monitor, intercept, and enforce policies on AI agents executing tool calls. Unlike self-reported or prompt-based guardrails, AgentShield operates as an out-of-band, authoritative gateway: an agent cannot execute actions on protected tools, networks, filesystems, or databases without an explicit cryptographic execution grant from AgentShield.

```
+-------------------------------------------------------------------------+
|                              AI Agent                                   |
| (OpenAI Agents SDK / Anthropic Claude / LangGraph / CrewAI / Google ADK)|
+-------------------------------------------------------------------------+
                                     │
               1. Request Execution  │ (Tool call, args, provenance)
                                     ▼
+-------------------------------------------------------------------------+
|                  AgentShield Controlled Gateway                         |
|   ┌───────────────────────┐         ┌───────────────────────────────┐   |
|   │ Authentication        │         │ Policy Engine (Priority,      │   |
|   │ (Agent Token / HMAC)  │         │ Deterministic, Zero-Eval)     │   |
|   └──────────┬────────────┘         └───────────────▲───────────────┘   |
|              │                                      │                   |
|              ▼                                      │                   |
|   ┌───────────────────────┐         ┌───────────────┴───────────────┐   |
|   │ Threat Detection      │────────▶│ Core Decision Engine          │   |
|   │ (PI, Exfil, Command)  │         │ (ALLOW / BLOCK / ASK_HUMAN)   │   |
|   └───────────────────────┘         └───────────────┬───────────────┘   |
|                                                     │                   |
|                                                     ▼                   |
|                                     ┌───────────────────────────────┐   |
|                                     │ Execution Grant Generator     │   |
|                                     │ (Single-use, HMAC bound)      │   |
|                                     └───────────────┬───────────────┘   |
+-----------------------------------------------------┼-------------------+
                                                      │
                                                      ▼ 2. Execution Grant
+-------------------------------------------------------------------------+
|                    Controlled Execution Boundary                        |
|   ┌─────────────────────────────────────────────────────────────────┐   |
|   │ Sandboxed Adapters: Shell / HTTP / Filesystem / Database        │   |
|   └────────────────────────────────┬────────────────────────────────┘   |
+------------------------------------┼------------------------------------+
                                     │
                                     ▼ 3. Real World Execution
                     [ External APIs / DB / OS / MCP ]
```

## 2. Core Architectural Pillars

### 2.1 Backend Authority (FastAPI)
The backend is the sole source of truth and enforcement. It executes:
- **Authentication & Multi-Tenancy**: Agent tokens, user JWTs (Argon2 password hashing), and tenant isolation.
- **Security Engine**: Deterministic policy evaluation, permission checks, and risk scoring ($0-100$).
- **Threat Detection Suite**: Prompt injection detector, data leakage/PII redactor, filesystem path traversals, shell command sanitizers, and behavioral anomaly detectors.
- **Execution Gateway**: Controlled boundary where registered tools run only if valid, single-use grants signed by the backend are presented.
- **Audit Logging**: Cryptographically hash-chained event logs ensuring non-repudiation.

### 2.2 Desktop Control Center (PySide6)
A native, responsive light-themed desktop application providing operators and security analysts with:
- Live real-time security telemetry over WebSockets.
- Human Approval Center for `ASK_HUMAN` interventions with timeout handling and audit logging.
- Policy Management with zero-eval rule builders and policy simulation sandboxes.
- Threat Monitoring, audit trail explorer, incident forensics, and system settings.

### 2.3 Integration Layer & Interceptors
- **Universal SDK Integration**: Drop-in adapters wrapping native agent tool registries (OpenAI Agents SDK, Claude, LangGraph, CrewAI, Google ADK).
- **Model Context Protocol (MCP) Gateway**: Intercepts MCP JSON-RPC protocol messages (`tools/call`, `resources/read`), performing parameter redaction, tool whitelisting, and SSRF prevention.

### 2.4 Data Layer (PostgreSQL & SQLite)
- **Primary**: PostgreSQL with async SQLAlchemy 2.0 and Alembic schema migrations.
- **Local / Edge**: Support for `sqlite+aiosqlite` for single-user offline development or edge deployments.
