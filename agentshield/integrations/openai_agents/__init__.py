"""
AgentShield AI — OpenAI Agents SDK Integration Package (Phase 7).
"""

from agentshield.integrations.openai_agents.adapter import OpenAIIntegrationAdapter
from agentshield.integrations.openai_agents.agent_factory import AgentShieldOpenAIAgent
from agentshield.integrations.openai_agents.client import AgentShieldOpenAIClient
from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.exceptions import (
    ApprovalPendingError,
    AuthenticationFailureError,
    BackendUnavailableError,
    InvalidToolArgumentsError,
    OpenAIIntegrationError,
    SecurityPolicyBlockError,
    ToolNotAllowedError,
    redact_secrets,
)
from agentshield.integrations.openai_agents.schemas import (
    AgentShieldToolResult,
    OpenAIAgentSessionSummary,
    OpenAIToolCall,
)
from agentshield.integrations.openai_agents.tool_wrapper import AgentShieldToolWrapper

__all__ = [
    "AgentShieldIntegrationConfig",
    "AgentShieldOpenAIAgent",
    "AgentShieldOpenAIClient",
    "AgentShieldToolResult",
    "AgentShieldToolWrapper",
    "ApprovalPendingError",
    "AuthenticationFailureError",
    "BackendUnavailableError",
    "InvalidToolArgumentsError",
    "OpenAIAgentSessionSummary",
    "OpenAIIntegrationAdapter",
    "OpenAIIntegrationError",
    "OpenAIToolCall",
    "SecurityPolicyBlockError",
    "ToolNotAllowedError",
    "redact_secrets",
]
