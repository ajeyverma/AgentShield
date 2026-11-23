# OpenAI Agents SDK Integration Guide — AgentShield AI

## 1. Architecture Overview

The OpenAI Agents SDK integration connects models running on the official `openai-agents` SDK directly to the AgentShield AI runtime security gateway.

```
USER
  │
  ▼
OpenAI Agents SDK Agent (gpt-4o-mini / gpt-4o)
  │
  ▼
AgentShield Tool Wrapper (FunctionTools)
  │ (Blocks unapproved tools locally via allowlist)
  ▼
AgentShield OpenAI Client (Authenticated HTTP)
  │ (Sends X-Agent-Credential header to /api/v1/executions)
  ▼
AgentShield FastAPI Gateway (Phase 6)
  ├── 1. Agent Authentication & Tenant Check (anti-spoofing)
  ├── 2. Tool & Action Schema Validation
  ├── 3. Phase 5 Threat Detection (Prompt Injection, Data Leaks, FS Traversal)
  ├── 4. Phase 4 Security Evaluation (ALLOW / BLOCK / ASK_HUMAN)
  └── 5. Single-Use Cryptographic Grant Issuance
  │
  ▼
Controlled Tool Adapters (calculator, sandbox_fs, mock_email, mock_http)
  │
  ▼
Sanitized Tool Result returned to Model
  │
  ▼
OpenAI Agent reasoning & user response
```

---

## 2. Key Security Properties

1. **Adapter Isolation:** The OpenAI model never has direct access to API credentials, raw filesystem paths, or outbound network sockets. Tool operations execute exclusively on the AgentShield server.
2. **Fail-Closed Execution:** If the AgentShield backend cannot be reached, requests default to `BLOCK`. The wrapper **never** executes tools locally as a fallback.
3. **Identity Anti-Spoofing:** The backend cryptographically validates the agent credential and enforces ownership. An agent cannot impersonate another agent's ID or change its tenant.
4. **Credential Separation:** The model provider API key (`OPENAI_API_KEY`) is used exclusively for LLM queries and is never transmitted to the AgentShield gateway. Agent credentials (`agt_...`) are never exposed to the LLM.

---

## 3. Installation & Supported SDK Version

- **Python:** 3.11+
- **OpenAI Agents SDK:** `openai-agents>=0.25.0`
- **OpenAI Client:** `openai>=3.0.0`

Installation:
```bash
pip install openai-agents>=0.25.0 openai>=3.0.0
```

---

## 4. Environment Configuration

```bash
# AgentShield Gateway Configuration
export AGENTSHIELD_BACKEND_URL="http://localhost:8000"
export AGENTSHIELD_AGENT_ID="<your-agent-uuid>"
export AGENTSHIELD_AGENT_CREDENTIAL="agt_<your-agent-secret-token>"

# Model Provider Configuration (used only by OpenAI SDK)
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o-mini"
```

---

## 5. Tool Allowlist Configuration

By default, the integration restricts exposed tools to an explicit allowlist:

```python
from agentshield.integrations.openai_agents import AgentShieldIntegrationConfig, AgentShieldOpenAIAgent

config = AgentShieldIntegrationConfig(
    agent_id="<agent-uuid>",
    agent_credential="agt_...",
    allowed_tools=["calculator", "sandbox_fs"],  # Expose only math & sandbox filesystem
)
agent = AgentShieldOpenAIAgent(config=config)
```

Tools outside the allowlist are omitted from the model prompt and will be blocked immediately if invoked.

---

## 6. Running the Demonstration

### Simulated Mode (No OpenAI Key Required)
Runs through the real in-process AgentShield Execution Gateway and demonstrates `ALLOW`, `BLOCK`, and `ASK_HUMAN`:
```bash
python examples/openai_agent_demo.py --simulate
```

### Live Interactive Mode (Requires `OPENAI_API_KEY`)
```bash
python examples/openai_agent_demo.py --prompt "Calculate 250 multiplied by 48."
```

---

## 7. Security Outcomes Handled

### 1. `ALLOW`
The gateway executes the operation and returns the real result:
```json
{"status": "SUCCESS", "result": {"operation": "multiply", "result": 12000.0}, "execution_id": "..."}
```

### 2. `BLOCK`
The gateway rejects the request and the adapter is never invoked:
```json
{"status": "BLOCKED", "error": "Path traversal sequence detected in filesystem request: '../../etc/shadow'.", "execution_id": "..."}
```

### 3. `ASK_HUMAN`
The operation pauses awaiting human authorization in the AgentShield desktop Approval Center:
```json
{"status": "PENDING_APPROVAL", "execution_id": "...", "approval_id": "...", "message": "This operation has been paused by AgentShield and requires human approval before proceeding."}
```

---

## 8. Crucial Security Limitation

> [!WARNING]
> The SDK wrapper enforces security **only for tool calls directed through AgentShield-wrapped tools**. If an agent possesses separate OS privileges (such as raw shell execution or direct outbound network access), it may bypass the integration layer. To achieve complete containment, run the agent in a network-isolated container with all outbound internet blocked except to the AgentShield gateway.
