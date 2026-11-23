# AgentShield AI — Security Model & Threat Boundary

## 1. Core Threat Philosophy

AgentShield operates under a zero-trust model regarding AI agents. AI agents are treated as untrusted runtime execution clients whose outputs and intended tool actions are subject to prompt injection, jailbreaking, hallucination, and adversarial compromise.

### The Three Security Decisions
All tool evaluation requests culminate in one of three deterministic decisions:

1. **ALLOW**:
   - The action satisfies all active security policies.
   - The composite risk score is below the tenant threshold ($< 40$).
   - Threat detectors report no active high-severity indicators.
   - An ephemeral, single-use, cryptographically signed execution grant is generated.

2. **BLOCK**:
   - The action violates an explicit deny policy, contains detected attacks (e.g. prompt injection, unauthorized privilege escalation, path traversal, shell injection), or exceeds maximum allowable risk ($\ge 75$).
   - Execution is immediately halted. A tamper-evident security audit record is logged.
   - **BLOCK decisions are immutable and can never be overridden by human operators or agent retries.**

3. **ASK_HUMAN**:
   - The action is within a high-impact risk band ($40 \le \text{risk} < 75$) or matches a policy condition requiring human consent (e.g., destructive actions, financial transfers, external email sending).
   - Execution is suspended pending review in the PySide6 Desktop Approval Center.
   - Rejection or expiration automatically resolves to **BLOCK**.

---

## 2. Threat Boundary & Guarantees

```
+─────────────────────────────────────────────────────────────+
| UNTRUSTED ZONE                                              |
| - AI Agent (LLM, weights, prompts, tools list)              |
| - Direct tool inputs (unfiltered JSON, untrusted arguments) |
+──────────────────────────────┬──────────────────────────────+
                               │ Gateway Boundary Interception
+──────────────────────────────▼──────────────────────────────+
| TRUSTED SECURITY ZONE (AgentShield Backend)                 |
| - Deterministic Policy Evaluator                            |
| - Threat Detection Engine (Regex, Heuristics, Redaction)    |
| - Cryptographic Grant Signer (HMAC-SHA256)                  |
| - Tamper-Evident Audit Ledger (SHA-256 Hash Chaining)       |
+──────────────────────────────┬──────────────────────────────+
                               │ Valid Grant Only
+──────────────────────────────▼──────────────────────────────+
| EXECUTION BOUNDARY                                          |
| - Sandboxed Tool Adapters (Shell, Network, Filesystem, DB)  |
| - Destination Execution (Protected Services)                |
+─────────────────────────────────────────────────────────────+
```

### Invariants:
1. **Zero Agent Self-Approval**: Agents have no authority to approve, bypass, or alter security decisions.
2. **Single-Use Execution Grants**: Grants are bound to the specific agent ID, tool name, argument hash, and timestamp, expiring after 60 seconds.
3. **Audit Non-Repudiation**: Audit logs form a linear hash chain; modifying past records invalidates all subsequent verification hashes.
