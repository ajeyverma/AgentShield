# AgentShield AI — Hybrid Deployment Guide

AgentShield AI is built from the ground up to support a **Hybrid Deployment Model**, combining local workstation developer ergonomics with enterprise-wide centralized security governance.

---

## 1. What is Hybrid Deployment?

In a Hybrid Deployment:
- **Desktop UI**: Runs natively on the security administrator or developer's workstation.
- **Local Interceptors**: Fast local proxies or agent SDK integrations intercepting tool calls on the development or test machine.
- **Remote Gateway Authority**: The Core Security Engine, Threat Detection, Policy Enforcement, and Audit Chaining run on a central enterprise server.
- **Fail-Closed Secure Sync**: Security policies and rules are authored centrally; local desktop clients manage policies and approvals via secure REST and WebSocket connections.

```
 Workstation (Developer / Analyst)           Enterprise Cloud / DC
+------------------------------------+      +--------------------------------+
|  AI Agent (Local Test Run)         |      |                                |
|         │                          |      |                                |
|         ▼                          |      |                                |
|  AgentShield SDK Adapter           |      |                                |
|         │                          |      |                                |
|         ▼ (HTTPS Gateway Call)     |      |                                |
|  ----------------------------------┼─────▶| AgentShield Security Backend   |
|                                    |      |  - Deterministic Policy Engine |
|  PySide6 Desktop Control Center    |      |  - Risk Scoring & Correlation  |
|  (Approvals, Monitoring, Policies) |◀════▶|  - Execution Grant Signer      |
|                                    | WSS  |  - Tamper-Evident Audit Log    |
+------------------------------------+      +--------------------------------+
```

---

## 2. Configuration for Hybrid Operators

### Desktop Application Connection
When launching the desktop application:
1. Open **Settings** or use the **First-Run Setup Wizard**.
2. Set **Backend URL** to the centralized enterprise instance, e.g.:
   `https://agentshield.corp.internal`
3. Provide your Multi-Factor Authenticated (MFA) operator credentials.
4. Verify connection status: The top-right status indicator will illuminate green (**CONNECTED**).

### Agent Configuration
Configure agent environments with the central gateway endpoint and tenant API key:

```ini
AGENTSHIELD_GATEWAY_URL=https://agentshield.corp.internal/api/v1/gateway
AGENTSHIELD_AGENT_ID=agent-dept-alpha-001
AGENTSHIELD_AGENT_TOKEN=agsh_live_sec_7f9a8b1c...
```

---

## 3. High-Latency & Network Partition Behavior

AgentShield adheres to a **Strict Fail-Closed** model:
- If a workstation agent loses network connectivity to the centralized security backend, tool calls **cannot** be executed.
- No cached or optimistic execution grants are issued.
- All failed evaluation attempts are logged locally in memory and flushed once connectivity is restored.
