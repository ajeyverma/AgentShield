# AgentShield AI — OpenAI Agents SDK Integration

This package provides the official AgentShield runtime security wrapper for applications built with the **OpenAI Agents SDK** (`openai-agents>=0.25.0`).

## Architecture & Guarantees
- **Non-Bypassable Mediation:** Tools exposed to the model (`calculator`, `sandbox_fs`, `mock_email`, `mock_http`) contain **zero local execution logic**. Every call is forwarded to the authenticated AgentShield gateway.
- **Fail-Closed:** Unreachable gateway or auth error defaults to `BLOCK`.
- **Credential Redaction:** Raw agent secrets (`agt_...`) and OpenAI API keys (`sk-...`) are scrubbed from logs and exceptions.

## Quickstart

```python
from agentshield.integrations.openai_agents import (
    AgentShieldIntegrationConfig,
    AgentShieldOpenAIAgent,
)

# 1. Configure credentials and allowed tools
config = AgentShieldIntegrationConfig(
    agent_id="<AGENT_ID>",
    agent_credential="<AGENT_CREDENTIAL>",
    allowed_tools=["calculator", "sandbox_fs"],
)

# 2. Build secured agent
agent = AgentShieldOpenAIAgent(config=config)

# 3. Run instructions
result = agent.run("Calculate 250 multiplied by 48.")
print(result.final_output)

# 4. View observability summary
summary = agent.get_session_summary()
print(f"Total intercepted calls: {summary.total_tool_calls}")
```

See [OPENAI_AGENTS_INTEGRATION.md](../../docs/OPENAI_AGENTS_INTEGRATION.md) for full architecture and configuration options.
