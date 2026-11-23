# AgentShield AI

**Universal Runtime Security Gateway for AI Agents**

[![Release](https://img.shields.io/badge/Release-v1.0.0--Final-blue.svg)](https://github.com/ajayver110125/AgentShield)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-green.svg)](https://fastapi.tiangolo.com)
[![PySide6](https://img.shields.io/badge/PySide6-6.7%2B-green.svg)](https://www.qt.io)
[![Tests](https://img.shields.io/badge/Tests-391%20Passed%20(1%20Skipped)-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-Apache--2.0-lightgrey.svg)](LICENSE)

---

## 1. Overview

**AgentShield AI** is an independent, out-of-band runtime security platform that provides mandatory authorization, threat detection, and policy enforcement for autonomous AI agents.

As AI agents gain access to operating systems, databases, internal APIs, and the Model Context Protocol (MCP), relying on in-prompt instructions ("guardrails") is inadequate to prevent security incidents. AgentShield sits directly in the execution path, decoupling tool invocation from tool execution.

An AI agent cannot execute a protected tool without obtaining a single-use, cryptographically signed **Execution Grant** from AgentShield.

### The Three Security Decisions

Every tool request is deterministically evaluated against three potential outcomes:

```
                  ┌───────────────────────────────────────────────┐
                  │          AgentShield Evaluation Engine        │
                  └───────────────────────┬───────────────────────┘
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                             │
            ▼                             ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
   │      ALLOW      │           │      BLOCK      │           │    ASK_HUMAN    │
   ├─────────────────┤           ├─────────────────┤           ├─────────────────┤
   │ Policy verified │           │ Attack detected │           │ Sensitive tool  │
   │ Risk < 40       │           │ Policy denied   │           │ 40 <= Risk < 75 │
   │ Ephemeral grant │           │ Risk >= 75      │           │ Pauses for HITL │
   │ issued to agent │           │ Immutable halt  │           │ approval in UI  │
   └─────────────────┘           └─────────────────┘           └─────────────────┘
```

---

## 2. Complete Phase Roadmap

All 12 planned development phases are fully implemented, verified, and documented:

| Phase | Subsystem | Status | Highlights |
|---|---|:---:|---|
| **Phase 1** | Project Foundation | ✅ Complete | Shared contracts, architecture, settings, logging |
| **Phase 2** | Desktop Interface | ✅ Complete | Native PySide6 light-themed console with 9 functional views |
| **Phase 3** | Backend & Database | ✅ Complete | FastAPI REST APIs, async SQLAlchemy 2.0, Alembic, Argon2 & JWT, WebSockets |
| **Phase 4** | Core Security Engine | ✅ Complete | Deterministic policy evaluation, domain rules, risk scoring ($0-100$) |
| **Phase 5** | Threat Detection Engine | ✅ Complete | Prompt injection, data leakage/PII redaction, path traversal, command injection |
| **Phase 6** | Controlled Execution Gateway | ✅ Complete | Mandatory execution boundary, sandboxed adapters, HMAC single-use grants |
| **Phase 7** | OpenAI Agents SDK Integration | ✅ Complete | Non-bypassable tool wrappers, fail-closed interception, strict tool allowlists |
| **Phase 8** | MCP Firewall Gateway | ✅ Complete | Protocol proxy for MCP (JSON-RPC/SSE), SSRF/STDIO shields, secret redactor |
| **Phase 9** | Multi-Framework Integrations | ✅ Complete | Adapters for Anthropic Claude, LangGraph, CrewAI, and Google ADK |
| **Phase 10** | Human Approval & Policies | ✅ Complete | HITL Approval Center, zero-eval declarative policy rules, simulation sandbox |
| **Phase 11** | Monitoring, Auditing & Testing | ✅ Complete | Centralized event logging, SHA-256 hash-chained audit ledger, red-team test suite |
| **Phase 12** | Packaging & Deployment | ✅ Complete | Docker, Compose, Nginx, Systemd, PyInstaller, Inno Setup, CI/CD, complete docs |

---

## 3. High-Level Architecture

```
+───────────────────────────────────────────────────────────────────────────+
|                         AI AGENT APPLICATION                             |
|    (OpenAI Agents SDK / Anthropic Claude / LangGraph / CrewAI / ADK)      |
+─────────────────────────────────────┬─────────────────────────────────────+
                                      │
               1. Request Execution   │ (Tool, Arguments, Provenance)
                                      ▼
+───────────────────────────────────────────────────────────────────────────+
|                 AGENTSHIELD SECURITY CONTROL PLANE                        |
|                                                                           |
|   ┌────────────────────────┐            ┌─────────────────────────────┐   |
|   │ Agent Authentication   │            │ Declarative Policy Engine   │   |
|   │ (Token / Tenant Match) │            │ (Deterministic, Zero-Eval)  │   |
|   └───────────┬────────────┘            └──────────────▲──────────────┘   |
|               │                                        │                  |
|               ▼                                        │                  |
|   ┌────────────────────────┐            ┌──────────────┴──────────────┐   |
|   │ Threat Detection Suite │───────────▶│ Core Decision Engine        │   |
|   │ (PI, Exfil, Command)   │            │ (ALLOW / BLOCK / ASK_HUMAN) │   |
|   └────────────────────────┘            └──────────────┬──────────────┘   |
|                                                        │                  |
|                                                        ▼                  |
|                                         ┌─────────────────────────────┐   |
|                                         │ Execution Grant Generator   │   |
|                                         │ (Single-Use, HMAC-SHA256)   │   |
|                                         └──────────────┬──────────────┘   |
+────────────────────────────────────────────────────────┼──────────────────+
                                                         │
                                                         ▼ 2. Valid Grant
+───────────────────────────────────────────────────────────────────────────+
|                CONTROLLED TOOL EXECUTION BOUNDARY                         |
|   ┌───────────────────────────────────────────────────────────────────┐   |
|   │ Sandboxed Tool Adapters: Shell / HTTP / Filesystem / Database     │   |
|   └───────────────────────────────────┬───────────────────────────────┘   |
+───────────────────────────────────────┼───────────────────────────────────+
                                        │
                                        ▼ 3. Real Execution
                         [ External APIs / OS / DB / MCP ]
```

---

## 4. Quick Start

### 4.1 Prerequisites
- Python 3.11+
- Git

### 4.2 Installation
```bash
git clone https://github.com/ajayver110125/AgentShield.git
cd AgentShield

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 4.3 Database Initialization
```bash
# Initialize and apply all migrations to head
python scripts/db_init.py
```

### 4.4 Start the Backend Server
```bash
# Option A: Foreground Uvicorn
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000 --reload

# Option B: Background Service Manager
python scripts/service_manager.py start
```

### 4.5 Launch the Desktop Management UI
```bash
python apps/desktop/main.py
```

---

## 5. Multi-Framework Integration Examples

### 5.1 OpenAI Agents SDK
```python
from agentshield.integrations.openai_agents import AgentShieldToolWrapper

@AgentShieldToolWrapper(
    gateway_url="http://127.0.0.1:8000",
    agent_id="finance-agent-01",
    agent_token="agsh_live_sec_...",
    tool_name="transfer_funds"
)
def transfer_funds(recipient_account: str, amount_usd: float):
    return payment_gateway.charge(recipient_account, amount_usd)
```

### 5.2 Anthropic Claude SDK
```python
from agentshield.integrations.anthropic import ShieldedClaudeToolRegistry

registry = ShieldedClaudeToolRegistry(
    gateway_url="http://127.0.0.1:8000",
    agent_id="claude-code-agent"
)
registry.register(name="execute_command", handler=run_shell)
response = client.messages.create(..., tools=registry.get_tool_definitions())
```

### 5.3 LangGraph
```python
from agentshield.integrations.langgraph import ShieldedToolNode

shielded_node = ShieldedToolNode(
    tools=[read_file, write_file],
    gateway_url="http://127.0.0.1:8000",
    agent_id="langgraph-editor"
)
workflow.add_node("tools", shielded_node)
```

---

## 6. Deployment Strategies

AgentShield supports three flexible deployment patterns:
- **Local Deployment**: Single-workstation testing with embedded SQLite and local PySide6 UI. See [docs/local-deployment.md](docs/local-deployment.md).
- **Remote Production**: Centralized server with Docker Compose, PostgreSQL, Nginx reverse proxy (TLS 1.3), and systemd service. See [docs/remote-deployment.md](docs/remote-deployment.md).
- **Hybrid Deployment**: Local developer environments connecting to an authoritative enterprise cloud gateway. See [docs/hybrid-deployment.md](docs/hybrid-deployment.md).

---

## 7. Verification & Testing

AgentShield maintains a comprehensive test suite covering unit tests, integration tests, multi-framework conformance, security regression, and red-team injection tests:

```bash
# Run full automated test suite
pytest tests/ -v -m "not live_openai"
```
**Test Results Baseline:**
- **Total Tests**: 392 items
- **Passed**: 391 passed
- **Skipped**: 1 skipped (requires live OpenAI API key)
- **Execution Time**: ~78s

---

## 8. Complete Documentation Index

| Guide | Description |
|---|---|
| [System Architecture](docs/architecture.md) | In-depth architecture breakdown and execution flow |
| [Installation Guide](docs/installation.md) | Workstation, server, and container installation instructions |
| [Local Deployment](docs/local-deployment.md) | Single-developer setup with SQLite and local service management |
| [Remote Deployment](docs/remote-deployment.md) | Production cloud deployment with Nginx, Docker, and PostgreSQL |
| [Hybrid Deployment](docs/hybrid-deployment.md) | Enterprise hybrid model connecting local IDEs to remote gateways |
| [Configuration Reference](docs/configuration.md) | Complete environment variable specification and validation CLI |
| [Security Model](docs/security-model.md) | Threat boundaries, invariants, risk scoring, and zero-trust philosophy |
| [Agent Integrations](docs/integrations.md) | Adapters for OpenAI, Claude, LangGraph, CrewAI, and Google ADK |
| [MCP Firewall Gateway](docs/mcp-gateway.md) | Model Context Protocol proxy, tool namespacing, and parameter inspection |
| [Agent Onboarding](docs/agent-onboarding.md) | Step-by-step registration and provisioning guide |
| [Database Management](docs/database-management.md) | Schema design, async SQLAlchemy, and automated Alembic migrations |
| [Backup & Recovery](docs/backup-and-recovery.md) | Automated backup, SHA-256 verification, and disaster restore |
| [Troubleshooting](docs/troubleshooting.md) | Common errors, gateway debugging, and connectivity remediation |
| [Upgrade & Rollback](docs/upgrade-and-rollback.md) | Zero-downtime upgrades, database migration safety, and rollback steps |
| [Operations Runbook](docs/operations-runbook.md) | Health checks, monitoring, telemetry, and emergency lockdown commands |
| [Release Process](docs/release-process.md) | Release engineering, semantic versioning, and CI/CD pipelines |
| [Known Limitations](docs/known-limitations.md) | Explicit architectural assumptions and threat detection limitations |
| [Phase 12 Release Report](docs/phase-12-release-report.md) | Formal engineering release sign-off and metrics |

---

## 9. License

AgentShield AI is licensed under the Apache 2.0 License.
