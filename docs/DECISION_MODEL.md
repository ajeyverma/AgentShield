# AgentShield AI — Decision Model & Examples

## Overview

The decision model produces one of three outcomes:
1. `ALLOW`: Authorizes the action to proceed.
2. `BLOCK`: Rejects the action immediately and stops execution.
3. `ASK_HUMAN`: Suspends execution and generates a pending approval request.

---

## Decision Precedence

$$\text{BLOCK} > \text{ASK\_HUMAN} > \text{ALLOW}$$

---

## Decision Examples

### 1. ALLOW Decision
```json
{
  "request_id": "123e4567-e89b-12d3-a456-426614174000",
  "decision_id": "999e4567-e89b-12d3-a456-426614174999",
  "decision": "ALLOW",
  "risk_score": 20.0,
  "risk_level": "LOW",
  "reasons": [
    "No blocking policy rules triggered.",
    "Risk [ToolSensitivity +20.0]: Tool interacts with host filesystem.",
    "Action authorized under 70.0 risk threshold."
  ],
  "matched_policies": [],
  "approval_required": false,
  "evaluation_duration_ms": 1.45
}
```

### 2. BLOCK Decision (Prohibited System Path)
```json
{
  "request_id": "123e4567-e89b-12d3-a456-426614174001",
  "decision_id": "888e4567-e89b-12d3-a456-426614174888",
  "decision": "BLOCK",
  "risk_score": 95.0,
  "risk_level": "CRITICAL",
  "reasons": [
    "Access to protected system path or secret file is prohibited: '/etc/shadow'."
  ],
  "matched_policies": [
    {
      "policy_id": "00000000-0000-0000-0000-000000000001",
      "policy_name": "Block Sensitive Path Access",
      "rule_id": "FS-001"
    }
  ],
  "approval_required": false,
  "evaluation_duration_ms": 0.82
}
```

### 3. ASK_HUMAN Decision (File Deletion)
```json
{
  "request_id": "123e4567-e89b-12d3-a456-426614174002",
  "decision_id": "777e4567-e89b-12d3-a456-426614174777",
  "decision": "ASK_HUMAN",
  "risk_score": 55.0,
  "risk_level": "HIGH",
  "reasons": [
    "File deletion or destructive operation on '/home/user/data.bin' requires human approval.",
    "Risk [ToolSensitivity +20.0]: Tool interacts with host filesystem.",
    "Risk [DestructiveOperation +35.0]: Destructive operation detected: 'delete'."
  ],
  "matched_policies": [
    {
      "policy_id": "00000000-0000-0000-0000-000000000002",
      "policy_name": "Require Approval for File Deletion",
      "rule_id": "FS-002"
    }
  ],
  "approval_required": true,
  "approval_id": "333e4567-e89b-12d3-a456-426614174333",
  "approval_timeout_seconds": 300,
  "evaluation_duration_ms": 2.15
}
```
