# Direct Bypass Limitations & Deployment Boundary Requirements

## 1. Architectural Scope & Definition

AgentShield AI operates as an **application-layer runtime security gateway**. It mediates tool invocations that are directed to the AgentShield API or through AgentShield-provided tool adapters.

---

## 2. Direct Bypass Threat Vectors

If an AI agent possesses the ability to execute arbitrary Python code or has direct local network access to external services, application-layer mediation alone cannot guarantee that the agent will not bypass the gateway:

| Potential Bypass Vector | Description | Architectural Mitigation |
|---|---|---|
| **Direct Socket / Egress Connections** | Agent process initiates direct raw TCP/HTTP outbound connections without calling AgentShield API. | Egress network firewalls, iptables / Windows Defender egress rules restricting all outbound traffic except to AgentShield. |
| **Direct Filesystem Access** | Agent runs in an environment with direct access to local disks or operating system APIs. | Containerization (Docker, cgroups), read-only root filesystems, OS process sandboxing. |
| **Stolen Backend Secrets** | Agent accesses API keys or credentials directly from disk or environment variables. | Strict credential isolation: tools and third-party API credentials reside exclusively on the AgentShield server. Agents never hold raw credentials. |
| **Local Process Execution** | Agent invokes `subprocess.Popen` or shell commands directly on host OS. | Process boundary isolation; running agent processes in unprivileged, rootless containers or VMs. |

---

## 3. Recommended Production Deployment Architecture

To achieve complete runtime enforcement, AgentShield must be paired with host-level and network-level security controls:

```
┌────────────────────────────────────────────────────────┐
│  AGENT ENVIRONMENT (Isolated Container / Sandbox)      │
│  - No direct internet access (all outbound blocked)    │
│  - No external API credentials in environment          │
│  - Only permitted network route: AgentShield Gateway    │
└───────────────────────────┬────────────────────────────┘
                            │ (Authenticated REST/mTLS)
                            ▼
┌────────────────────────────────────────────────────────┐
│  AGENTSHIELD RUNTIME GATEWAY                           │
│  - Threat Detection (Prompt injection, leak detector)  │
│  - Core Security Decision Engine                       │
│  - Human Approval Workflow                             │
│  - Controlled Tool Adapters holding target credentials │
└───────────────────────────┬────────────────────────────┘
                            │ (Controlled Execution)
                            ▼
┌────────────────────────────────────────────────────────┐
│  PROTECTED RESOURCES & EXTERNAL APIS                   │
│  - Databases, SaaS APIs, Filesystems, Terminal         │
└────────────────────────────────────────────────────────┘
```

By ensuring that the AI agent process has **no direct outbound networking** and **no credentials**, all interactions are strictly forced through AgentShield's Controlled Execution Gateway.
