# Incident Response & Alert Engine

## 1. Alert Rules & Correlation

AgentShield uses a deterministic sliding-window alert engine (`SecurityAlertEngine`) that evaluates events without flaky AI-based guesswork:

| Rule ID | Name | Trigger Condition | Severity | Cooldown |
|---|---|---|---|---|
| `RULE_REPEATED_BLOCKS` | Repeated Policy Blocks | $\ge 3$ BLOCK decisions in 60s | HIGH | 60s |
| `RULE_HIGH_TOOL_FREQUENCY` | High Tool Frequency | $\ge 20$ tool requests in 10s | MEDIUM | 30s |
| `RULE_PROMPT_INJECTION_CLUSTER` | Prompt Injection Cluster | $\ge 2$ prompt injection findings in 120s | CRITICAL | 120s |
| `RULE_DATA_EXFILTRATION` | Potential Data Exfiltration | $\ge 1$ data leakage threat finding | CRITICAL | 60s |
| `RULE_DANGEROUS_COMMAND` | Destructive Command Detected | $\ge 1$ catastrophic command threat | CRITICAL | 60s |
| `RULE_CROSS_TENANT` | Cross-Tenant Access Attempt | $\ge 1$ unauthorized tenant attempt | CRITICAL | 30s |
| `RULE_EMERGENCY_LOCKDOWN` | Emergency Lockdown Activated | $\ge 1$ emergency control activation | CRITICAL | 10s |

---

## 2. Incident Management Lifecycle

Incidents enforce a strict state machine:

```
[OPEN] ──► [ACKNOWLEDGED] ──► [INVESTIGATING] ──► [RESOLVED] ──► [CLOSED]
```

- **OPEN**: Created from an alert or manually by a security operator.
- **ACKNOWLEDGED**: Assigned to an analyst; initial triage complete.
- **INVESTIGATING**: Actively collecting evidence, auditing agent logs, reviewing threat findings.
- **RESOLVED**: Remediated (e.g. agent disabled, policy tightened, prompt updated).
- **CLOSED**: Final sign-off recorded with mandatory explanation.

Every status transition is cryptographically logged in the audit trail.
