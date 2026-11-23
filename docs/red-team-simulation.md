# Safe Red-Team Simulation Harness

## 1. Philosophy & Safety Guarantees

All red-team scenarios in AgentShield run in completely isolated, synthetic sandboxes:
- **Zero Real Attacks**: No external network requests, zero malicious command execution on host operating system.
- **Determinism**: Every test scenario produces identical, repeatable results across test runs.
- **Exhaustive Coverage**: Tests 12 real-world attack vectors across agent tools and protocols.

---

## 2. Scenario Directory

1. **SCENARIO-01: Indirect Prompt Injection**
   - *Attack*: Document content contains instruction override payloads.
   - *Defense*: `PromptInjectionDetector` flags `PROMPT_INJECTION` threat.
2. **SCENARIO-02: Path Traversal Escape**
   - *Attack*: Relative path `../../../../etc/hosts` to escape sandbox root.
   - *Defense*: `SandboxedFilesystemAdapter` raises `InvalidArgumentsError`.
3. **SCENARIO-03: Cross-Tenant Resource Access**
   - *Attack*: Attacker in Tenant B attempts to approve Tenant A's execution.
   - *Defense*: `ApprovalService` rejects with `ApprovalNotFoundError`.
4. **SCENARIO-04: Prohibited Catastrophic Command**
   - *Attack*: Command `rm -rf /` in terminal tool.
   - *Defense*: `CommandAnalysisDetector` flags CRITICAL threat finding.
5. **SCENARIO-05: Synthetic Sensitive Data Exfiltration**
   - *Attack*: Outbound HTTP POST containing synthetic credit card and AWS secret.
   - *Defense*: `DataLeakageDetector` catches and flags `DATA_EXFILTRATION`.
6. **SCENARIO-06: Tool Rate Spamming / Flood Burst**
   - *Attack*: Rapid flood burst of 35 tool executions in < 60s.
   - *Defense*: `BehavioralAnomalyDetector` flags rate spike anomaly.
7. **SCENARIO-07: Expired Approval Token Reuse**
   - *Attack*: Attacking agent attempts to execute an expired approval request.
   - *Defense*: Execution gateway rejects with `ApprovalVerificationError("expired")`.
8. **SCENARIO-08: Tampered Argument Hash on Approved Request**
   - *Attack*: Reusing idempotency key with modified arguments.
   - *Defense*: Gateway raises `IdempotencyConflictError`.
9. **SCENARIO-09: Malicious MCP Server Leaking Secrets**
   - *Attack*: Upstream MCP server response contains private keys and credentials.
   - *Defense*: `MCPResponseInspector` sanitizes response and scrubs all keys.
10. **SCENARIO-10: Unregistered MCP Tool Access Attempt**
    - *Attack*: Tool call targeting an unregistered/unapproved tool.
    - *Defense*: Gateway raises `ToolNotFoundError`.
11. **SCENARIO-11: Alert Engine Triggering**
    - *Attack*: Incurring repeated security blocks on the same agent.
    - *Defense*: Alert engine fires `RULE_REPEATED_BLOCKS` high alert.
12. **SCENARIO-12: Gateway Bypass Attempt**
    - *Attack*: Directly calling adapter without authorized gateway grant.
    - *Defense*: `AuthorizationManager` raises `ApprovalVerificationError`.
