# AgentShield AI

**Universal Runtime Security Gateway for AI Agents**

[![Phase](https://img.shields.io/badge/Phase-4%20Core%20Security%20Engine-blue)]()
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-green)]()
[![PySide6](https://img.shields.io/badge/PySide6-6.7%2B-green)]()
[![Tests](https://img.shields.io/badge/Tests-161%20Passed-brightgreen)]()

---

## Overview

AgentShield AI is an independent runtime security layer for AI agents. It monitors, intercepts, and controls tool invocations across external APIs, files, databases, and terminals, evaluating permissions, policies, and risk to make three authoritative decisions:

| Decision | Meaning |
|----------|---------|
| **ALLOW** | Permit an authorized and safe action |
| **BLOCK** | Prevent an unauthorized or dangerous action |
| **ASK_HUMAN** | Suspend action and require authorized human approval |

Security decisions are independently computed and enforced by AgentShield's backend — never by the AI agent itself.

---

## Architecture & Progress

| Phase | Component | Status | Highlights |
|-------|-----------|--------|------------|
| **Phase 1** | Project Foundation | ✅ Complete | Shared contracts, settings, and base architecture |
| **Phase 2** | Desktop Interface | ✅ Complete | Light-themed PySide6 application shell with 9 management views |
| **Phase 3** | Backend & Database | ✅ Complete | FastAPI REST APIs, SQLAlchemy 2.0 ORM, Alembic migrations, Argon2 & JWT auth, real-time WebSockets |
| **Phase 4** | Core Security Engine | ✅ Complete | Deterministic decision engine, domain rules, permission engine, risk scoring (0-100), policy conflict resolution |
| **Phase 5** | Threat Detection Engine | ✅ Complete | Modular detectors (Prompt Injection, Data Leakage, Filesystem, Commands, Network, Behavioral), Correlation Engine |
| **Phase 6+** | Integrations & Execution Gateway | ⏳ Planned | SDK adapters, MCP gateway, controlled execution |

---

## Quick Start

### 1. Database Migrations
```bash
python -m alembic upgrade head
```

### 2. Start Backend API Server
```bash
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Start PySide6 Desktop Application
```bash
python apps/desktop/main.py
```

### 4. Run Automated Test Suite (211 Tests)
```bash
pytest tests/ -v
```

---

## Documentation

- [Threat Detection Engine](docs/THREAT_DETECTION.md)
- [Prompt Injection Detection](docs/PROMPT_INJECTION.md)
- [Data Leakage & Redaction](docs/DATA_LEAKAGE_DETECTION.md)
- [Provenance Model](docs/PROVENANCE_MODEL.md)
- [Behavioral Anomaly Analysis](docs/BEHAVIORAL_ANALYSIS.md)
- [Threat Correlation](docs/THREAT_CORRELATION.md)
- [Detection Limitations](docs/DETECTION_LIMITATIONS.md)
- [Core Security Engine](docs/SECURITY_ENGINE.md)
- [Policy Evaluation Engine](docs/POLICY_ENGINE.md)
- [Risk Scoring Methodology](docs/RISK_SCORING.md)
- [Decision Model & Examples](docs/DECISION_MODEL.md)
- [API Contracts](docs/API_CONTRACTS.md)
- [System Architecture](docs/ARCHITECTURE.md)
