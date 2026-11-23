# Phase 11 Architecture: Monitoring, Auditing & Observability

## 1. Overview & Objectives

AgentShield AI Phase 11 introduces a production-ready monitoring, auditing, incident response, and advanced security testing subsystem. Built to mediate and authorize all tool executions across AI agent frameworks (OpenAI Agents SDK, Anthropic Claude SDK, LangGraph, CrewAI, Google ADK, and MCP), Phase 11 guarantees deterministic observability, append-only cryptographic auditability, and verifiable protection boundaries.

```
                           AI Agent Frameworks & MCP Clients
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │   AgentShield Execution Gateway        │
                      │  (Idempotency, Token Auth, Controls)  │
                      └───────────────────┬───────────────────┘
                                          │
                 ┌────────────────────────┴────────────────────────┐
                 ▼                                                 ▼
     ┌───────────────────────┐                         ┌───────────────────────┐
     │  Core Security Engine │                         │ Threat Detection Core │
     │  & Policy Evaluator   │                         │ (Static & Behavioral) │
     └───────────┬───────────┘                         └───────────┬───────────┘
                 │                                                 │
                 └────────────────────────┬────────────────────────┘
                                          │
                        ┌─────────────────▼─────────────────┐
                        │    Unified Event & Tracing Core   │
                        │    (Contextvars, Scrubbing, Pub)  │
                        └─────────────────┬─────────────────┘
                                          │
         ┌────────────────────────────────┼────────────────────────────────┐
         ▼                                ▼                                ▼
┌──────────────────┐            ┌──────────────────┐            ┌──────────────────┐
│ Tamper-Evident   │            │ Real-Time Alert  │            │ In-Memory        │
│ Audit Service    │            │ Engine           │            │ Metrics Engine   │
│ (SHA-256 Chain)  │            │ (Sliding Windows)│            │ (p50/p95/p99)    │
└────────┬─────────┘            └────────┬─────────┘            └────────┬─────────┘
         │                               │                               │
         ▼                               ▼                               ▼
 PostgreSQL / SQLite             PostgreSQL / SQLite            REST API & Dashboards
  (AuditLog & Checkpoints)       (Alerts & Incidents)            (PySide6 Desktop)
```

---

## 2. Core Subsystems

### 2.1 Unified Security Event Core
Every component emits standardized `SecurityEvent` contracts containing:
- Server-generated UUID4 `event_id`.
- UTC timestamps (`timestamp`).
- Distributed tracing context (`trace_id`, `span_id`, `parent_span_id`, `correlation_id`).
- Tenant isolation identifier (`tenant_id`) and actor identifier (`actor_id`).
- Categorization metadata (`source_component`, `event_type`, `severity`).
- Automatic recursive secret scrubbing via `redact_secrets()`.

### 2.2 Distributed Tracing & Observability
- Context-variable backed span hierarchy (`TraceSpan`).
- 32-hex trace IDs and 16-hex span IDs propagating across async tasks.
- Component-level latency capture with non-sensitive attribute tracking.

### 2.3 Tamper-Evident Hash-Chained Audit Trail
- Sequential monotonically increasing sequence numbers ($1, 2, \dots$).
- Cryptographic SHA-256 hash chaining:
  $$H_i = \text{SHA256}(\text{canonical\_payload}_i \parallel H_{i-1})$$
  with $H_0 = 0^{64}$ (genesis hash).
- Full cryptographic chain verification detecting any modification, deletion, or reordering.
- Periodic cryptographic checkpoints anchoring verified chain state.

### 2.4 Deterministic Alert Engine & Incident Management
- Stateful sliding-window rules (`RULE_REPEATED_BLOCKS`, `RULE_HIGH_TOOL_FREQUENCY`, `RULE_PROMPT_INJECTION_CLUSTER`, `RULE_DATA_EXFILTRATION`, `RULE_DANGEROUS_COMMAND`, `RULE_CROSS_TENANT`, `RULE_EMERGENCY_LOCKDOWN`).
- Alert deduplication and cooldown timers preventing alert storms.
- Strict incident response lifecycle: `OPEN` $\to$ `ACKNOWLEDGED` $\to$ `INVESTIGATING` $\to$ `RESOLVED` $\to$ `CLOSED`.
