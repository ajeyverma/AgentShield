# AgentShield AI — Controlled Tool Execution Gateway

## Overview

The **Controlled Tool Execution Gateway** introduced in Phase 6 establishes the mandatory runtime enforcement boundary between AI agents and external resources. Unlike passive logging or monitoring tools, the gateway mediates execution: **no protected tool can execute unless the gateway explicitly authorizes and executes it through a controlled server-side adapter.**

---

## 1. Gateway Lifecycle & Execution Flow

Every tool invocation mediated by the gateway executes through a deterministic, fail-closed pipeline:

```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Agent
    participant Gateway as Controlled Gateway (API)
    participant Auth as Agent Auth & Tenant Check
    participant Reg as Tool Registry & Schema Validator
    participant Threat as Phase 5 Threat Detection
    participant Sec as Phase 4 Security Engine
    participant GrantMgr as Execution Authorization Manager
    participant Human as Human Approver (PySide6 / REST)
    participant Adapter as Controlled Tool Adapter

    Agent->>Gateway: POST /api/v1/executions (agent_id, tool, action, args)
    Gateway->>Auth: Verify Agent & User Ownership
    Auth-->>Gateway: Authenticated
    Gateway->>Reg: Validate Tool & Action Schema
    Reg-->>Gateway: Validated ToolDefinition
    Gateway->>Threat: Run Threat Detection (Prompt Injection, Leaks, Traversal)
    Threat-->>Gateway: Threat Findings & Composite Score
    Gateway->>Sec: Authoritative Decision Evaluation
    Sec-->>Gateway: Decision (ALLOW / BLOCK / ASK_HUMAN)

    alt Decision == BLOCK
        Gateway-->>Agent: 200 OK (status: BLOCKED, result: null)
        Note over Gateway,Adapter: Tool Adapter is NEVER invoked
    else Decision == ASK_HUMAN
        Gateway-->>Agent: 200 OK (status: PENDING_APPROVAL, approval_id: UUID)
        Note over Gateway,Adapter: Execution paused; Adapter is NOT invoked
        Human->>Gateway: POST /api/v1/executions/{id}/approve
        Gateway->>GrantMgr: Issue & Consume Single-Use Grant (SHA256 bound)
        Gateway->>Adapter: Execute Action with verified arguments
        Adapter-->>Gateway: ToolExecutionResult
        Gateway-->>Human: 200 OK (status: COMPLETED, result: data)
    else Decision == ALLOW
        Gateway->>GrantMgr: Issue & Consume Single-Use Grant
        Gateway->>Adapter: Execute Action
        Adapter-->>Gateway: ToolExecutionResult
        Gateway-->>Agent: 200 OK (status: COMPLETED, result: data)
    end
```

---

## 2. Key Architectural Guarantees

1. **Adapter Isolation:**
   Tool adapters are private to the backend server. Agents never hold API credentials, direct filesystem handles, or network sockets to the underlying capabilities.

2. **Fail-Closed Enforcement:**
   If authentication fails, schemas mismatch, or an unexpected error occurs during security evaluation, the gateway defaults to `BLOCK`. Tool adapters are never invoked on error.

3. **Mandatory Policy Primacy:**
   If a security policy or domain rule evaluates to `BLOCK`, human approval cannot override it. The approval route explicitly checks for mandatory blocks and rejects override attempts.

4. **Idempotency Guarantees:**
   Clients submitting an `idempotency_key` receive cached execution results on network retries. If an attacker replays an idempotency key with modified arguments, the gateway raises an `IdempotencyConflictError` and rejects the request.

---

## 3. Execution Lifecycle States

| State | Description |
|---|---|
| `RECEIVED` | Execution request received and parsed by the API gateway. |
| `VALIDATING` | Identity verified; tool, action, and arguments checked against schemas. |
| `EVALUATING` | Threat detection (Phase 5) and security decision engine (Phase 4) executing. |
| `BLOCKED` | Action rejected by security rules or threat detectors. Tool adapter is never called. |
| `PENDING_APPROVAL` | Action paused requiring human authorization. Adapter is not called. |
| `APPROVED` | Human approver verified and approved the pending request. |
| `EXECUTING` | Single-use grant consumed; tool adapter running within isolation sandbox. |
| `COMPLETED` | Execution completed successfully; outputs stored and returned. |
| `FAILED` | Tool adapter reported failure or exceeded timeout/output limits. |
| `EXPIRED` | Approval window elapsed without human authorization. |
| `CANCELLED` | Execution explicitly cancelled by human operator before execution. |

---

## 4. REST API Endpoints

- `POST /api/v1/executions`: Submit execution request for controlled evaluation.
- `GET /api/v1/executions`: List execution audit history with pagination and status filters.
- `GET /api/v1/executions/{id}`: Retrieve detailed execution state, arguments hash, and outputs.
- `POST /api/v1/executions/{id}/approve`: Submit verified human approval notes and trigger execution.
- `POST /api/v1/executions/{id}/cancel`: Abort a pending approval request.
- `GET /api/v1/tools`: List all registered tools and their available actions.
- `GET /api/v1/tools/{tool_name}`: Inspect specific tool schemas, timeouts, and risk classifications.
