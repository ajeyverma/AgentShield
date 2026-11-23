"""
AgentShield AI — Shared Integration Core Package (Phase 9).
"""

from agentshield.integrations.core.agent_identity import AgentIdentity
from agentshield.integrations.core.base_adapter import BaseFrameworkAdapter
from agentshield.integrations.core.conformance import IntegrationConformanceVerifier
from agentshield.integrations.core.exceptions import (
    ApprovalPendingError,
    AuthenticationFailureError,
    BackendUnavailableError,
    FrameworkNotInstalledError,
    IntegrationError,
    InvalidToolArgumentsError,
    SecurityPolicyBlockError,
    ToolNotAllowedError,
    redact_secrets,
)
from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.integration_registry import IntegrationRegistry, integration_registry
from agentshield.integrations.core.result_handler import AgentShieldToolResult
from agentshield.integrations.core.tool_wrapper import CANONICAL_TOOLS, BaseToolWrapper, ToolInvocationRecord

__all__ = [
    "AgentShieldIntegrationConfig",
    "AgentIdentity",
    "BaseFrameworkAdapter",
    "BaseToolWrapper",
    "ToolInvocationRecord",
    "CANONICAL_TOOLS",
    "AgentShieldToolResult",
    "AgentShieldExecutionClient",
    "IntegrationRegistry",
    "integration_registry",
    "IntegrationConformanceVerifier",
    "IntegrationError",
    "AuthenticationFailureError",
    "BackendUnavailableError",
    "ToolNotAllowedError",
    "SecurityPolicyBlockError",
    "ApprovalPendingError",
    "InvalidToolArgumentsError",
    "FrameworkNotInstalledError",
    "redact_secrets",
]
