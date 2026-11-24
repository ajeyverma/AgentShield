# AgentShield AI — Agent Integration Matrix

**Audit Date:** November 24, 2026  
**Auditor:** Antigravity Automated Verification System  
**Stage:** Stage 1 Post-Development Integration Audit  
**Target Version:** AgentShield v0.1.0  
**Overall Integration Status:** **PASS**

---

## 1. Overview & Mediation Strategy

AgentShield acts as a protective runtime boundary between autonomous agents and external execution surfaces (tools, APIs, databases, filesystems, and shell runners). To support diverse multi-agent architectures, AgentShield provides both framework-agnostic wrappers and specialized adapters for the leading industry agent frameworks.

Every adapter intercepts the agent's proposed action, translates it into an `AgentShieldToolCallRequest`, transmits it to the policy/decision engine, and only executes the underlying function if an authorization token or `ALLOW` decision is returned.

---

## 2. Framework Integration Matrix

| Framework | Adapter Module | Interception Mechanism | Token Handling | Fallback / Fail-Closed | Test Suite | Status |
|---|---|---|---|---|---|---|
| **Claude Agent SDK** | `agentshield.integrations.claude_agent_sdk` | Client & Tool Wrapper (`ClaudeAgentShieldClient`) | Injects single-use execution token into request context | Blocks on 401/403 or policy denial; aborts tool call | `tests/integrations/test_claude.py` | **PASS** |
| **LangGraph** | `agentshield.integrations.langgraph` | Custom Pre-Tool Node / Middleware (`AgentShieldLangGraphAdapter`) | Intercepts node transitions; checks state & tool calls | Halts graph step; routes to human node on `ASK_HUMAN` | `tests/integrations/test_adapters.py` | **PASS** |
| **CrewAI** | `agentshield.integrations.crewai` | Tool Execution Interceptor (`AgentShieldCrewAITool`) | Validates agent capability against tenant policy | Returns synthetic security error string to agent loop | `tests/integrations/test_adapters.py` | **PASS** |
| **Google ADK** | `agentshield.integrations.google_adk` | Function Calling Interceptor (`GoogleADKShieldWrapper`) | Generates signed audit verification hash | Rejects unauthorized function call before client dispatch | `tests/integrations/test_adapters.py` | **PASS** |
| **OpenAI Agents** | `agentshield.integrations.openai_agents` | Tool Runner Proxy (`OpenAIAgentShieldProxy`) | Enforces signed token on custom and assistant tools | Returns refusal message or blocks execution loop | `tests/integrations/test_adapters.py`<br>`test_optional_live_openai.py` (live mocked) | **PASS** |
| **Generic Python SDK** | `agentshield.integrations.sdk` | Decorator (`@agentshield_protect`) & Context Manager | Verifies token via local or remote execution gateway | Raises `SecurityPolicyViolationError` | `tests/execution/test_gateway.py` | **PASS** |
| **MCP Servers** | `agentshield.mcp_gateway` | stdio & SSE Reverse Proxy (`MCPProxyServer`) | Validates `tools/call` JSON-RPC requests | Drops call with JSON-RPC error `-32001 (Blocked)` | `tests/mcp/test_mcp_proxy.py` | **PASS** |

---

## 3. Detailed Verification by Framework

### 3.1 Claude Agent SDK (`claude_agent_sdk`)
- **Architecture:** Intercepts Anthropic tool definitions (`tools=[...]`) and the tool-execution loop. 
- **Verification Evidence:** `tests/integrations/test_claude.py` confirms that when an unapproved tool call (e.g. `execute_bash` with dangerous arguments) is triggered, the client catches the policy violation, logs an audit entry, and refuses tool execution.
- **Verdict: PASS**

### 3.2 LangGraph (`langgraph`)
- **Architecture:** Provides a stateful node interceptor compatible with LangGraph state graphs. When an agent decides to invoke a tool, the AgentShield node evaluates the planned action. If `ASK_HUMAN` is returned, the graph pauses its state and transitions to a human approval state.
- **Verification Evidence:** `tests/integrations/test_adapters.py` confirms graph halting and resumption upon token presentation.
- **Verdict: PASS**

### 3.3 CrewAI (`crewai`)
- **Architecture:** Wraps CrewAI `BaseTool` instances. During `_run()` and `_arun()`, tool inputs are sent through `RiskScoringEngine` and `PolicyEngine`.
- **Verification Evidence:** Unit tests verify that agent role-based restrictions (e.g. researcher vs. executor) are strictly enforced.
- **Verdict: PASS**

### 3.4 Google Agent Development Kit (`google_adk`)
- **Architecture:** Intercepts Gemini function calls before execution. Validates parameter taint status and denies execution of untrusted system operations.
- **Verification Evidence:** Unit tests verify schema compliance and deterministic block execution.
- **Verdict: PASS**

### 3.5 OpenAI Agents (`openai_agents`)
- **Architecture:** Intercepts OpenAI Assistants API tool outputs and client-side function calling.
- **Verification Evidence:** Unit tests mock OpenAI responses and verify gateway policy enforcement. (Note: Live API tests in `tests/integration/test_optional_live_openai.py` are conditionally skipped when `OPENAI_API_KEY` is not present in local environment; mocked tests pass completely).
- **Verdict: PASS**

### 3.6 Model Context Protocol (MCP Gateway)
- **Architecture:** Fully transparent proxy supporting standard stdio and SSE transport.
- **Verification Evidence:** `tests/mcp/test_mcp_proxy.py` and `tests/mcp/test_tool_filter.py` verify that `list_tools` hides unauthorized tools and `call_tool` blocks disallowed invocations.
- **Verdict: PASS**

---

## 4. Integration Limitations & Best Practices

1. **Instrumentation Requirement:** Agents must be instantiated with the respective AgentShield wrapper or connect through the MCP gateway. Unwrapped agent instances running in an unrestricted Python runtime cannot be constrained by application-level software alone.
2. **Asynchronous Execution:** All adapters are implemented natively for `asyncio` with synchronous bridging wrappers (`async_to_sync`) to support legacy synchronous agent runtimes without deadlocking.

---

## 5. Summary Verdict

All targeted agent frameworks (Claude, LangGraph, CrewAI, Google ADK, OpenAI, Generic SDK, and MCP) have operational, tested adapter implementations that adhere to AgentShield's fail-closed execution model.

**Agent Integration Verdict: PASS**
