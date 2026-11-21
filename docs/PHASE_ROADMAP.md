# AgentShield AI — Phase Roadmap

---

## Phase 1 — Project Foundation ✅ (Current)

**Goal:** Establish a clean, scalable foundation.

**Deliverables:**
- Project structure and dependency management (`pyproject.toml`)
- Shared Pydantic contracts: `ActionRequest`, `SecurityDecision`, all enums
- Centralized configuration system (local/remote modes, env vars)
- FastAPI backend skeleton with `/health` endpoint and versioned API prefix
- PySide6 desktop skeleton with light theme design tokens
- Abstract integration interfaces for SDK and MCP adapters
- SQLAlchemy async session configuration (PostgreSQL + SQLite)
- Domain exception hierarchy
- Structured logging
- Automated tests (unit, integration, security contract)
- Full documentation set
- Docker + Docker Compose foundation

---

## Phase 2 — Backend Core & Identity

**Goal:** Build the backend foundation for agent identity, authentication, and audit.

**Planned deliverables:**
- JWT-based authentication (login, token refresh)
- Tenant model and registration
- Agent connector registration and management
- Database migrations (Alembic)
- Core ORM models (Tenant, Agent, AuditEvent, ApprovalRequest)
- Audit log recording (append-only, structured)
- WebSocket event stream for real-time desktop updates
- Desktop: Backend client service (httpx-based)

---

## Phase 3 — Security Core

**Goal:** Implement the actual security evaluation engine.

**Planned deliverables:**
- Policy model and storage
- Policy engine (rule evaluation)
- Risk scoring engine
- Basic threat detection (heuristic rules)
- `POST /api/v1/evaluate` endpoint
- Decision persistence in audit log
- Policy management API
- Desktop: Policy viewer

---

## Phase 4 — Human Approvals & Execution Gateway

**Goal:** Implement human-in-the-loop workflows and controlled execution.

**Planned deliverables:**
- Approval request creation and lifecycle management
- `GET /api/v1/approvals/{id}` and `POST /api/v1/approvals/{id}/respond`
- Approval timeout and expiry
- Execution authorization tokens (signed, single-use)
- Execution gateway with token validation
- Desktop: Approval queue and notification UI

---

## Phase 5 — SDK Integrations

**Goal:** Deliver the first real AI framework integrations.

**Planned deliverables:**
- OpenAI Agents SDK adapter
- LangGraph adapter
- Google ADK adapter
- Generic Python agent SDK (`agentshield-sdk`)
- Integration test harnesses

---

## Phase 6 — MCP Integration

**Goal:** Deliver the MCP transparent proxy.

**Planned deliverables:**
- MCP proxy server
- Tool call interception for all MCP-compatible clients
- MCP server registry
- Claude agent integration via MCP

---

## Phase 7 — Desktop Dashboard

**Goal:** Build the full monitoring and management UI.

**Planned deliverables:**
- Sidebar navigation
- Live activity feed (WebSocket)
- Connected agents list
- Decision history viewer
- Threat alerts panel
- Approval queue management

---

## Phase 8 — Policy Management UI

**Goal:** Full policy authoring and management in the desktop app.

**Planned deliverables:**
- Policy builder UI
- Rule library
- Policy testing / simulation
- Policy import/export

---

## Phase 9 — Threat Detection & Analytics

**Goal:** Advanced threat detection and behavioral analytics.

**Planned deliverables:**
- Behavioral baseline per agent
- Anomaly scoring
- Threat feed integration
- Risk trend charts in desktop app

---

## Phase 10 — Multi-Tenant & Enterprise Features

**Goal:** Enterprise readiness.

**Planned deliverables:**
- Full multi-tenant isolation
- Role-based access control (RBAC)
- SSO / OAuth integration
- Audit log export
- Compliance reporting

---

## Phase 11 — Additional Integrations

**Goal:** Broaden integration coverage.

**Planned deliverables:**
- CrewAI adapter
- Claude SDK direct adapter
- Additional MCP server connectors
- Webhook integration for external approval systems

---

## Phase 12 — Production Hardening

**Goal:** Production-ready release.

**Planned deliverables:**
- Security penetration testing
- Performance benchmarking and optimization
- Full Docker production configuration
- Kubernetes deployment manifests
- Comprehensive documentation
- Release packaging
