# AgentShield AI — Security Decision Engine

## Overview

The AgentShield Core Security Engine provides independent, deterministic, and explainable runtime authorization for AI agent tool invocations.

The engine evaluates actions without relying on an LLM or the agent's own safety claims.

---

## Evaluation Flow

```mermaid
flowchart TD
    Req[ActionRequest] --> V1{Identity & Ownership Valid?}
    V1 -- No --> B1[BLOCK - Identity Mismatch]
    V1 -- Yes --> V2{Agent Active?}
    V2 -- No --> B2[BLOCK - Agent Deactivated]
    V2 -- Yes --> V3{Permissions Conforming?}
    V3 -- Explicit Deny --> B3[BLOCK - Permission Denied]
    V3 -- Missing Permission --> B4[BLOCK - Deny by Default]
    V3 -- Granted --> V4[Evaluate Domain & User Policies]
    V4 --> V5{Mandatory Block Triggered?}
    V5 -- Yes --> B5[BLOCK - Policy Violation]
    V5 -- No --> V6[Calculate Risk Score 0-100]
    V6 --> V7{Requires Human Approval?}
    V7 -- Yes --> A1[ASK_HUMAN - Approval Request Created]
    V7 -- No --> AL[ALLOW - Action Authorized]
```

---

## Core Tenets

1. **Deny by Default:** Unless an action is explicitly granted in the agent's permission profile, it is denied.
2. **Explicit Deny Overrides Allow:** Deny configurations take absolute precedence.
3. **Mandatory Block Precedence:** High-severity policy violations cannot be bypassed by an allow rule or converted into an approval request.
4. **Decision Precedence:** `BLOCK` > `ASK_HUMAN` > `ALLOW`.
5. **Fail-Closed Guarantee:** Any unexpected runtime evaluation failure catches the exception, logs securely without leaking secrets, and returns an immediate safe `BLOCK` decision.
