# AgentShield AI

**Universal Runtime Security Gateway for AI Agents**

[![Phase](https://img.shields.io/badge/Phase-1%20Foundation-blue)]()
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-green)]()
[![PySide6](https://img.shields.io/badge/PySide6-6.7%2B-green)]()

---

## Overview

AgentShield AI is a security platform that acts as an independent enforcement layer between AI agents and the tools they use. It monitors, intercepts, and controls every tool call made by AI agents, applying security policy and making three possible decisions:

| Decision | Meaning |
|----------|---------|
| **ALLOW** | Permit an authorized and safe action |
| **BLOCK** | Prevent an unauthorized or dangerous action |
| **ASK_HUMAN** | Pause until an authorized human approves |

Security decisions are made by the AgentShield backend — not by the AI agent itself.

---

## Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Desktop Application | Python + PySide6 | Security monitoring dashboard |
| Security Backend | Python + FastAPI | Security enforcement and policy evaluation |
| Integration Layer | Python SDKs + MCP | Intercept tool calls from AI frameworks |

---

## Quick Start

### Prerequisites

- Python 3.11 or higher
- pip

### 1. Clone and set up environment

```bash
git clone <repository-url>
cd agentshield-ai

# Create a virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate
```

### 2. Install dependencies

```bash
# Core shared contracts only
pip install -e .

# Backend API dependencies
pip install -e ".[api]"

# Desktop application dependencies
pip install -e ".[desktop]"

# Development / testing tools
pip install -e ".[dev]"

# Everything
pip install -e ".[all]"
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env to set your database URL, secret key, etc.
```

### 4. Start the backend

```bash
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Health check:
```bash
curl http://localhost:8000/api/v1/health
```

### 5. Start the desktop application

```bash
python apps/desktop/main.py
```

### 6. Run tests

```bash
pytest
```

---

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the full development guide.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the system architecture.

## Security Model

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for security design decisions.

## API Contracts

See [docs/API_CONTRACTS.md](docs/API_CONTRACTS.md) for the shared data contracts.

## Phase Roadmap

See [docs/PHASE_ROADMAP.md](docs/PHASE_ROADMAP.md) for the 12-phase development plan.

---

## Project Status

**Phase 1 — Foundation** ✅

The project foundation, architecture, shared contracts, backend skeleton, and desktop skeleton are established.

---

## License

Proprietary — All rights reserved.
