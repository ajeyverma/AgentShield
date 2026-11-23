"""
Forwarding alias for integrations.openai_agents -> agentshield.integrations.openai_agents.
"""

from agentshield.integrations.openai_agents import (
    AgentShieldIntegrationConfig,
    AgentShieldOpenAIAgent,
    AgentShieldOpenAIClient,
    AgentShieldToolResult,
    AgentShieldToolWrapper,
    ApprovalPendingError,
    AuthenticationFailureError,
    BackendUnavailableError,
    InvalidToolArgumentsError,
    OpenAIAgentSessionSummary,
    OpenAIIntegrationAdapter,
    OpenAIIntegrationError,
    OpenAIToolCall,
    SecurityPolicyBlockError,
    ToolNotAllowedError,
    redact_secrets,
)

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
