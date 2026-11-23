# Approval and Execution Security Model

## 1. Threat Model & Security Objectives

In an AI runtime gateway, client-side claims cannot be trusted:
1. **Client-Forged Permissions:** An AI agent cannot grant itself an `ALLOW` decision.
2. **Argument Tampering:** An agent cannot request approval for a benign action (`read_file("doc.txt")`) and then execute a dangerous action (`read_file("../../etc/shadow")`) using the same approval token.
3. **Approval Replay:** A single human approval cannot be reused to execute an action multiple times.
4. **Cross-Tenant Impersonation:** User B cannot approve or view executions belonging to User A.
5. **Approval Override Bypass:** Human approval cannot bypass a mandatory `BLOCK` resulting from security policy violations or high-risk threat findings.

---

## 2. Cryptographic Argument Binding

All execution requests compute a canonical SHA-256 argument hash before security analysis:

$$\text{CanonicalHash} = \text{SHA256}(\text{JSON}(\text{arguments, sort\_keys=True, separators=(',', ':')}))$$

This canonical hash is immutably stored in the `ToolExecutionModel` and bound to the server-issued `ExecutionAuthorizationGrant`.

---

## 3. Single-Use Execution Authorization Grants

The `ExecutionAuthorizationManager` issues ephemeral, single-use grants:
- **`grant_id`:** Cryptographically random UUID4.
- **`request_id`:** Bound to original client request.
- **`agent_id` / `user_id`:** Strict identity binding.
- **`argument_hash`:** Must match canonical argument hash.
- **`expires_at`:** Short-lived window (default 60 seconds).
- **`is_used`:** Atomic single-use state.

When an adapter is invoked (whether immediately via `ALLOW` or deferred via human approval), the gateway calls `consume_grant()`:
1. Verifies the grant exists in memory.
2. Verifies `is_used == False`.
3. Verifies `now <= expires_at`.
4. Verifies `grant.argument_hash == request.canonical_argument_hash`.
5. Verifies `grant.agent_id == request.agent_id`.
6. Marks `is_used = True`.

Any second attempt to invoke the adapter with the same grant raises an immediate `ApprovalVerificationError` with replay attack detection alerts.

---

## 4. Human Approval Verification Pipeline

When an action triggers `ASK_HUMAN`:
1. The execution is placed in `PENDING_APPROVAL` status and an `ApprovalRequest` record is persisted.
2. The PySide6 Desktop application receives a real-time `execution.approval_required` WebSocket event.
3. The human operator reviews the tool, action, argument summary, risk score, and threat findings in the Approval Center.
4. When approved:
   - The caller must be authenticated as the owning user.
   - The execution must currently be in `PENDING_APPROVAL` status.
   - The approval window must not have expired.
   - The execution's original decision must not be `BLOCK`.
   - The stored canonical arguments are restored from the database, a fresh grant is issued and consumed, and the adapter is executed.
