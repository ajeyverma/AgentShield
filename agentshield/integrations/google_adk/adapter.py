"""Google ADK integration adapter for AgentShield AI."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.base_adapter import BaseFrameworkAdapter
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.agent_identity import AgentIdentity
from agentshield.integrations.core.integration_registry import integration_registry
from agentshield.integrations.core.result_handler import AgentShieldToolResult
from agentshield.integrations.google_adk.tool_wrapper import GoogleADKToolWrapper
from agentshield.integrations.google_adk.agent import AgentShieldGoogleAgent


class GoogleADKIntegrationAdapter(BaseFrameworkAdapter):
    """Adapter for integrating Google ADK and Gemini agents with AgentShield."""

    def __init__(self, config: AgentShieldIntegrationConfig) -> None:
        super().__init__(config)
        self.tool_wrapper = GoogleADKToolWrapper(self.client, self.config)

    @property
    def framework_type(self) -> IntegrationType:
        return IntegrationType.SDK_GOOGLE_ADK

    @property
    def framework_name(self) -> str:
        return "Google Agent Development Kit"

    def get_wrapped_tools(self) -> List[Dict[str, Any]]:
        """Return framework-compatible wrapped tools for only permitted allowlisted tools."""
        return self.tool_wrapper.get_function_declarations()

    def execute_tool(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
    ) -> AgentShieldToolResult:
        """Execute a tool call through AgentShield."""
        return self.tool_wrapper.route_tool_call(
            tool_name=tool_name,
            action_name=action_name,
            arguments=arguments,
            approval_id=approval_id,
        )

    def create_agent(
        self,
        agent_name: str = "GoogleSecureAgent",
        model_name: str = "gemini-2.5-flash",
    ) -> AgentShieldGoogleAgent:
        """Create an AgentShieldGoogleAgent."""
        return AgentShieldGoogleAgent(tool_wrapper=self.tool_wrapper, agent_name=agent_name, model_name=model_name)


# Register with global registry
integration_registry.register_adapter_class(IntegrationType.SDK_GOOGLE_ADK, GoogleADKIntegrationAdapter)
