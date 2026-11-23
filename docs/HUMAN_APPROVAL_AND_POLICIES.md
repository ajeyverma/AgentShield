# AgentShield AI — Phase 10: Human Approval and Policy Management

## 1. Overview & Architecture

Phase 10 introduces the complete Human-in-the-Loop (HITL) security management system for AgentShield AI. It bridges runtime tool execution mediation, role-based governance, declarative policy authoring, safe policy simulation, and instant incident response controls.

The architecture enforces a strict boundary between AI agents and human administrators:

```
                  ┌──────────────────────────────────────────────┐
                  │          AI Agent Tool Invocation            │
                  │  (OpenAI, Claude, LangGraph, CrewAI, ADK)    │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │    Controlled Execution Gateway (Phase 6)     │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │    Core Security & Threat Detection Engine   │
                  │      • Mandatory Domain BLOCK Rules          │
                  │      • Active Policies by Priority           │
                  │      • Structured Conditions (Safe Ops)      │
                  └──────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
           [Decision: ALLOW]                               [Decision: ASK_HUMAN]
                 │                                               │
                 ▼                                               ▼
     ┌───────────────────────┐                       ┌───────────────────────┐
     │ Execute Tool Adapter  │                       │ Execution Suspended;  │
     │ Return Result         │                       │ ApprovalRequest bound │
     └───────────────────────┘                       │ to Canonical Hash     │
                                                     └───────────┬───────────┘
                                                                 │
                                                       [WebSocket Notification]
                                                                 │
                                                                 ▼
                                                     ┌───────────────────────┐
                                                     │ PySide6 Desktop UI /  │
                                                     │ Human Approval Center │
                                                     │  • Sanitized Args     │
                                                     │  • Threat Breakdown   │
                                                     │  • RBAC Authorization │
                                                     └───────────┬───────────┘
                                                                 │
                                             ┌───────────────────┴───────────────────┐
                                             │                                       │
                                     [Human: APPROVE]                        [Human: REJECT]
                                             │                                       │
                                             ▼                                       ▼
                                 ┌───────────────────────┐               ┌───────────────────────┐
                                 │ Gateway re-validates  │               │ Execution marked      │
                                 │ hash, checks emergency│               │ BLOCKED/CANCELLED.    │
                                 │ controls, executes    │               │ Zero adapter call.    │
                                 │ single-use grant.     │               └───────────────────────┘
                                 └───────────────────────┘
```

---

## 2. Core Security & Safety Guarantees

### 2.1 Zero Agent Self-Approval
- AI agents are strictly forbidden from approving requests.
- `assert_not_agent_self_approval()` enforces at the database and service boundary that neither caller credentials nor agent IDs match reviewer identities.

### 2.2 Strict One-Time Approval Binding
- An approval is bound cryptographically to:
  1. The exact `execution_id`
  2. The canonical argument SHA-256 hash
  3. The tenant and user ID
  4. The expiration timestamp
- Once approved or rejected, the approval cannot be reused or replayed (`ApprovalVerificationError`).
- Any tampering with arguments causes an instant hash mismatch rejection.

### 2.3 Non-Overridable Mandatory BLOCK Decisions
- If an action violates a fundamental domain rule or emergency control, the security core issues a mandatory `BLOCK`.
- Mandatory `BLOCK` decisions cannot be converted to `ASK_HUMAN` and cannot be overridden by human approvers.

### 2.4 Separation of Duties & RBAC Risk Thresholds
- **User Roles:**
  - `OWNER`: Full administrative, policy, approval, and emergency control.
  - `SECURITY_ADMIN`: Policy authoring, high-risk approvals, and emergency control.
  - `APPROVER`: Authorized for Low and Medium risk approvals only.
  - `AUDITOR`: Read-only access to audit logs, approval histories, and policies.
  - `VIEWER`: Read-only access to policies and agents.
- **High-Risk Guardrail:** Any action with risk score $\ge 70$ or severity `HIGH`/`CRITICAL` requires explicit authorization by `OWNER` or `SECURITY_ADMIN`. Ordinary `APPROVER` users are rejected.

### 2.5 Secret Redaction & Sanitization
- `redact_secrets()` recursively scrubs arguments, tokens, and credentials from all approval inspection endpoints, audit logs, and real-time WebSocket events.
- Bearer tokens, API keys (`sk-...`, `ghp_...`, `ash_...`), private keys, and sensitive dictionary keys (`password`, `token`, `secret`, `api_key`) are masked with `[REDACTED]`.

---

## 3. Declarative Policy Management & Structured Conditions

Policies are evaluated strictly in ascending order of priority integer (Priority `1` evaluates before Priority `100`).

### Precedence Hierarchy:
1. **Emergency Controls**: Active lockdown or disabled agent/tool $\to$ Immediate `BLOCK`.
2. **Mandatory Domain Rules**: Fundamental safety violations $\to$ Immediate `BLOCK`.
3. **Explicit Blocking Policies**: Policy decision `BLOCK` $\to$ Immediate `BLOCK`.
4. **Approval Required Policies**: Policy decision `ASK_HUMAN` $\to$ Immediate suspension for human review.
5. **Explicit Permissive Policies**: Policy decision `ALLOW` (evaluated in priority order).
6. **Default Deny**: If no policy allows the action $\to$ Block.

### Safe Structured Condition Evaluation:
- All policy conditions use safe declarative operators:
  - `equals`, `not_equals`
  - `contains`, `not_contains`
  - `starts_with`, `ends_with`
  - `greater_than`, `less_than`, `greater_than_or_equal`, `less_than_or_equal`
  - `in`, `not_in`
  - `matches_pattern` (safe regex)
- **Zero arbitrary code execution:** Absolutely no `eval()`, `exec()`, or dynamic runtime code.

---

## 4. Policy Simulation Engine

The **Policy Simulator** (`POST /api/v1/policies/simulate`) allows administrators to safely preview how policies, rules, and detectors evaluate synthetic action requests:
- Safe synthetic execution sandbox.
- Runs against active in-database policies and real-time threat detectors.
- **Zero tool adapter execution:** No files are touched, no commands executed, no external networks queried.
- Returns simulated decision, matched policy, priority, risk score, and detected threat findings.

---

## 5. Emergency Security Controls (Lockdown & Kill-Switch)

Provides immediate, fail-closed incident response mechanisms:
- `PAUSE_EXECUTIONS`: Instantly halts all tool executions across the entire gateway.
- `EMERGENCY_DENY_MODE`: Default-denies all operations regardless of permissive policies.
- `DISABLE_AGENT`: Disables a specific compromised agent.
- `DISABLE_TOOL`: Blocks calls to a specific tool or vulnerable adapter.
- `DISABLE_INTEGRATION` / `DISABLE_MCP_SERVER`: Cuts off upstream integrations or MCP connections.
- Revocation restores normal policy evaluation with full audit tracking.

---

## 6. REST API Reference

| Method | Endpoint | Description | Required Permission |
|---|---|---|---|
| `GET` | `/api/v1/approvals` | List approvals (filters: status, agent, tool, search) | `approval:read` |
| `GET` | `/api/v1/approvals/{id}` | Get detail with redacted args and threat breakdown | `approval:read` |
| `POST` | `/api/v1/approvals/{id}/approve` | Approve request and resume gateway execution | `approval:approve` |
| `POST` | `/api/v1/approvals/{id}/reject` | Reject request and halt tool execution | `approval:approve` |
| `POST` | `/api/v1/approvals/{id}/cancel` | Cancel request | `approval:approve` |
| `GET` | `/api/v1/approvals/{id}/history` | Get immutable state transition audit history | `approval:read` |
| `GET` | `/api/v1/policies` | List configured policies ordered by priority | `policy:read` |
| `POST` | `/api/v1/policies` | Create policy with scopes, priority, and conditions | `policy:write` |
| `GET` | `/api/v1/policies/conflicts` | Detect overlapping scopes and decision clashes | `policy:read` |
| `POST` | `/api/v1/policies/simulate` | Run safe synthetic simulation | `policy:read` |
| `PATCH` | `/api/v1/policies/{id}` | Update policy and record new version snapshot | `policy:write` |
| `POST` | `/api/v1/policies/{id}/duplicate` | Duplicate policy as a draft | `policy:write` |
| `GET` | `/api/v1/policies/{id}/history` | Get version snapshots of a policy | `policy:read` |
| `GET` | `/api/v1/security/emergency-status` | Get lockdown status and active emergency controls | Authenticated |
| `POST` | `/api/v1/security/emergency-controls` | Activate emergency control / lockdown | `emergency:execute` |
| `POST` | `/api/v1/security/emergency-controls/{id}/revoke` | Revoke emergency control | `emergency:execute` |
