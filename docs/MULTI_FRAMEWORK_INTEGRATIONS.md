# AgentShield AI — Multi-Framework AI Agent Integrations (Phase 9)

## 1. Overview & Architectural Philosophy

AgentShield AI delivers a **universal runtime security gateway and firewall** for autonomous AI agents. Rather than relying on disparate, vendor-specific security plugins or client-side trust assumptions, AgentShield intercepts, authenticates, analyzes, and mediates every tool invocation through a centralized, policy-driven Controlled Tool Execution Gateway.

Phase 9 expands AgentShield beyond single-framework integrations (such as the Phase 7 OpenAI Agents SDK adapter and Phase 8 MCP Firewall Gateway) into a **shared, framework-independent integration architecture** supporting five industry-standard AI agent frameworks:

1. **OpenAI Agents SDK** (`integrations/openai_agents/`) — Direct function and hosted tool mediation.
2. **Anthropic Claude Agent SDK** (`integrations/claude_agent_sdk/`) — Tool use block interception & Anthropic tool schema formatting.
3. **LangGraph** (`integrations/langgraph/`) — Graph-native `AgentShieldToolNode` with approval pause/interrupt handling.
4. **CrewAI** (`integrations/crewai/`) — Hierarchical multi-agent crew tracking, least-privilege delegation, and provenance enforcement.
5. **Google Agent Development Kit (Google ADK)** (`integrations/google_adk/`) — Gemini `FunctionDeclaration` translation and turn response mediation.

```
+-------------------------------------------------------------------------------------------------------+
|                                    Autonomous AI Agent Frameworks                                     |
|  +--------------------+  +--------------------+  +--------------------+  +--------------------------+ |
|  | Anthropic Claude   |  |     LangGraph      |  |       CrewAI       |  |        Google ADK        | |
|  | Tool Use API Hooks |  | AgentShieldToolNode|  | Multi-Agent Crews  |  | Function Calling Engine  | |
|  +---------+----------+  +---------+----------+  +---------+----------+  +------------+-------------+ |
+------------|-----------------------|-----------------------|--------------------------|---------------+
             |                       |                       |                          |
             v                       v                       v                          v
+-------------------------------------------------------------------------------------------------------+
|                               Shared Core Integration Framework (Phase 9)                             |
|                                                                                                       |
|  - Universal Tool Wrapper (`BaseToolWrapper`) & Allowlist Filtering                                   |
|  - Multi-Agent Identity & Provenance Tracking (`AgentIdentity`)                                      |
|  - Standardized Result Handler (`AgentShieldToolResult`)                                              |
|  - Centralized Integration Registry (`integration_registry`)                                          |
|  - Robust Fail-Closed Execution Client (`AgentShieldExecutionClient`)                                 |
+---------------------------------------------------+---------------------------------------------------+
                                                    |
                                                    | Authenticated REST / WebSocket (mTLS, API Key, Token)
                                                    v
+-------------------------------------------------------------------------------------------------------+
|                               AgentShield Server-Side Execution Gateway                               |
|                                                                                                       |
|  +-----------------------------+  +--------------------------------+  +----------------------------+  |
|  |     Security Core Engine    |  |    Threat Detection Engine     |  | Controlled Execution Engine|  |
|  |  ALLOW / BLOCK / ASK_HUMAN  |  |  Traversal / SSRF / Injection  |  | Canonical Protected Tools  |  |
|  +-----------------------------+  +--------------------------------+  +----------------------------+  |
+-------------------------------------------------------------------------------------------------------+
```

---

## 2. Shared Core Architecture (`agentshield.integrations.core`)

All framework adapters share unified foundational primitives located in `agentshield/integrations/core/`:

| Component | Class / Module | Purpose |
| :--- | :--- | :--- |
| **Configuration** | `AgentShieldIntegrationConfig` | Validated connection parameters, API prefixes, tool allowlists, fail-closed toggle, and credential masking. |
| **Identity & Lineage** | `AgentIdentity` | Multi-agent identity tracking, parent-child delegation lineage, tenant boundaries, and least-privilege scoping. |
| **Gateway Client** | `AgentShieldExecutionClient` | HTTP/async client dispatching tool calls to the Controlled Tool Execution Gateway with secret scrubbing. |
| **Result Handler** | `AgentShieldToolResult` | Normalized response contract providing `.is_allowed()`, `.is_blocked()`, `.is_pending_approval()`, and `.to_model_output()`. |
| **Tool Wrapper** | `BaseToolWrapper` | Tool allowlist enforcement, canonical schema lookup (`CANONICAL_TOOLS`), composite naming resolution, and invocation logging. |
| **Framework Adapter** | `BaseFrameworkAdapter(ABC)` | Common lifecycle and execution interface implemented by every framework connector. |
| **Registry** | `IntegrationRegistry` | Global singleton managing adapter registration, instantiation, and discovery. |
| **Conformance Suite**| `IntegrationConformanceVerifier` | Standard test suite asserting the 24 security conformance invariants. |

---

## 3. Supported AI Agent Frameworks

### 3.1 Anthropic Claude Agent SDK
- **Package:** `agentshield.integrations.claude_agent_sdk` (alias: `integrations.claude_agent_sdk`)
- **Key Classes:** `ClaudeIntegrationAdapter`, `ClaudeToolWrapper`, `AgentShieldClaudeAgent`
- **Tool Schema Format:** Standard Anthropic Claude JSON Schema (`{"name": "...", "description": "...", "input_schema": {...}}`).
- **Turn Interception:** Intercepts Claude `tool_use` blocks (`type: "tool_use"`), validates allowlists, sends calls to AgentShield, and formats returns as Anthropic `tool_result` content blocks.
- **Approval Handling:** When `ASK_HUMAN` occurs, emits a non-fatal `tool_result` error block alerting Claude that the operation is paused awaiting human approval (`appr-...`).

### 3.2 LangGraph
- **Package:** `agentshield.integrations.langgraph` (alias: `integrations.langgraph`)
- **Key Classes:** `LangGraphIntegrationAdapter`, `LangGraphToolWrapper`, `AgentShieldLangGraphTool`, `AgentShieldToolNode`
- **Graph State Integration:** Drop-in `AgentShieldToolNode` directly added to any `StateGraph` (`builder.add_node("tools", tool_node)`).
- **Execution Flow:** Extracts `tool_calls` from the state message list, executes each call through AgentShield, and returns standard `ToolMessage` updates.
- **Workflow Interruption:** High-risk actions resulting in `ASK_HUMAN` automatically set `agentshield_interrupted: True`, enabling native LangGraph checkpoint pause and resumption upon human authorization.

### 3.3 CrewAI
- **Package:** `agentshield.integrations.crewai` (alias: `integrations.crewai`)
- **Key Classes:** `CrewAIIntegrationAdapter`, `CrewAIToolWrapper`, `AgentShieldCrewTool`, `AgentShieldCrewMember`
- **Tool Pattern:** Subclasses CrewAI tool interfaces with `_run(**kwargs)` and `run(**kwargs)`.
- **Multi-Agent Hierarchy:** Tracks agent roles, goals, and parent-child delegation chains.
- **Least-Privilege Enforcement:** When a parent agent delegates tasks to a sub-agent (`lead.delegate_to(...)`), the sub-agent's permissions are restricted to the strict intersection of parent permissions and child scopes. A sub-agent can **never** escalate privileges or invoke tools unauthorized for its parent.

### 3.4 Google Agent Development Kit (Google ADK)
- **Package:** `agentshield.integrations.google_adk` (alias: `integrations.google_adk`)
- **Key Classes:** `GoogleADKIntegrationAdapter`, `GoogleADKToolWrapper`, `AgentShieldGoogleAgent`
- **Schema Format:** Formats allowed tools into Google GenAI `FunctionDeclaration` definitions and `genai_types.Tool` structures.
- **Turn Mediation:** Intercepts Gemini function call turns, routes invocations through AgentShield, and converts results into standard `function_response` dictionary representations.

---

## 4. Multi-Framework Comparison Matrix

| Security / Functional Dimension | Anthropic Claude SDK | LangGraph | CrewAI | Google ADK | OpenAI Agents SDK |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Integration Type** | `SDK_CLAUDE` | `SDK_LANGGRAPH` | `SDK_CREWAI` | `SDK_GOOGLE_ADK` | `SDK_OPENAI` |
| **Native Tool Format** | Tool Use JSON Schema | LangChain `BaseTool` / Callable | CrewAI `BaseTool` (`_run`) | GenAI `FunctionDeclaration` | `function_tool` / Callables |
| **Zero Local Execution** | Yes (100% Mediated) | Yes (100% Mediated) | Yes (100% Mediated) | Yes (100% Mediated) | Yes (100% Mediated) |
| **Fail-Closed Default** | Yes (Unreachable = BLOCK) | Yes (Unreachable = BLOCK) | Yes (Unreachable = BLOCK) | Yes (Unreachable = BLOCK) | Yes (Unreachable = BLOCK) |
| **Approval Interruption** | `tool_result` pause signal | Graph interruption state | Workflow pause signal | `function_response` pause | Pending approval tool result |
| **Multi-Agent Lineage** | AgentIdentity metadata | StateGraph node correlation | Parent/Child least privilege | Turn agent metadata | Session identity |
| **Secret Redaction** | Yes (`redact_secrets`) | Yes (`redact_secrets`) | Yes (`redact_secrets`) | Yes (`redact_secrets`) | Yes (`redact_secrets`) |

---

## 5. Security Invariants & Conformance (24 Conformance Checks)

Every integration adapter in AgentShield is validated against 24 universal security conformance checks:

1. **ALLOW Execution:** Safe tool operations forward directly to the gateway and return complete data.
2. **BLOCK Enforcement:** High-risk or policy-violating operations are halted immediately; the underlying tool is **never** executed.
3. **ASK_HUMAN Mediation:** Sensitive operations generate persistent approval IDs and pause model loops without executing.
4. **Allowlist Pre-Filtering:** Tools not in the agent's configured allowlist are rejected locally without leaking network requests.
5. **Fail-Closed Guarantee:** Unreachable or timing-out backend services trigger immediate denial; no fail-open behavior is permitted.
6. **Credential Decoupling:** Model provider keys (OpenAI, Anthropic, Google) are strictly decoupled from AgentShield security tokens.
7. **Secret Redaction:** Passwords, API keys (`sk-...`, `agt_...`), and Bearer tokens are scrubbed from logs and exceptions.
8. **Lineage Scoping:** Sub-agents spawned via delegation inherit only restricted permission subsets.

---

## 6. Running Example Demonstrations

All framework adapters include runnable demonstration scripts supporting both `--simulate` (deterministic local gateway emulation) and live backend execution:

```bash
# 1. Anthropic Claude SDK Demo
python examples/claude_agent/run_agent.py --simulate

# 2. LangGraph StateGraph Demo
python examples/langgraph/run_graph.py --simulate

# 3. CrewAI Multi-Agent Delegation Demo
python examples/crewai/run_crew.py --simulate

# 4. Google ADK / Gemini Demo
python examples/google_adk/run_adk.py --simulate
```
