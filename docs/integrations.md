# AgentShield AI — Multi-Framework Integrations Guide

AgentShield AI provides a universal runtime security layer compatible with major modern AI agent orchestration frameworks.

---

## 1. Supported Frameworks

AgentShield provides native adapters and conformance tests for five major agent ecosystems:

1. **OpenAI Agents SDK** (`agentshield.integrations.openai_agents`)
2. **Anthropic Claude Agent SDK** (`agentshield.integrations.anthropic`)
3. **LangGraph** (`agentshield.integrations.langgraph`)
4. **CrewAI** (`agentshield.integrations.crewai`)
5. **Google Agent Development Kit (ADK)** (`agentshield.integrations.google_adk`)

---

## 2. Universal Integration Architecture

Every integration adheres to the **AgentShield Interceptor Pattern**:
1. Intercepts tool invocation before execution.
2. Formats arguments and metadata into an `AgentShieldToolCallRequest`.
3. Submits request to AgentShield Gateway.
4. If `ALLOW`: Receives execution grant, runs tool, and validates result.
5. If `BLOCK`: Raises `AgentShieldSecurityException` back to the agent reasoning loop.
6. If `ASK_HUMAN`: Pauses execution, subscribes to resolution event, and resumes only upon explicit approval.

---

## 3. Quick Integration Examples

### 3.1 OpenAI Agents SDK
```python
from agentshield.integrations.openai_agents import AgentShieldToolWrapper

# Wrap native Python function tool
@AgentShieldToolWrapper(
    gateway_url="http://127.0.0.1:8000",
    agent_id="finance-agent-01",
    agent_token="agsh_live_sec_...",
    tool_name="database_query"
)
def run_db_query(query: str):
    return db.execute(query)
```

### 3.2 LangGraph Tool Interception
```python
from agentshield.integrations.langgraph import ShieldedToolNode

tools = [read_file, execute_bash]
shielded_node = ShieldedToolNode(
    tools=tools,
    gateway_url="http://127.0.0.1:8000",
    agent_id="langgraph-researcher"
)
builder.add_node("tools", shielded_node)
```

### 3.3 CrewAI Tool Decorator
```python
from agentshield.integrations.crewai import ShieldedBaseTool

class SecureSearchTool(ShieldedBaseTool):
    name: str = "WebSearch"
    description: str = "Performs external web searches."

    def _run(self, query: str) -> str:
        return search_api(query)
```
