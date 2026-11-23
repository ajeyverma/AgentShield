"""CrewAI integration adapter for AgentShield AI."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.base_adapter import BaseFrameworkAdapter
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.agent_identity import AgentIdentity
from agentshield.integrations.core.integration_registry import integration_registry
from agentshield.integrations.core.result_handler import AgentShieldToolResult
from agentshield.integrations.crewai.tool_wrapper import CrewAIToolWrapper, AgentShieldCrewTool
from agentshield.integrations.crewai.crew import AgentShieldCrewMember


class CrewAIIntegrationAdapter(BaseFrameworkAdapter):
    """Adapter for integrating CrewAI agents and multi-agent crews with AgentShield."""

    def __init__(self, config: AgentShieldIntegrationConfig) -> None:
        super().__init__(config)
        self.tool_wrapper = CrewAIToolWrapper(self.client, self.config)

    @property
    def framework_type(self) -> IntegrationType:
        return IntegrationType.SDK_CREWAI

    @property
    def framework_name(self) -> str:
        return "CrewAI"

    def get_wrapped_tools(self) -> List[AgentShieldCrewTool]:
        """Return framework-compatible wrapped tools for only permitted allowlisted tools."""
        return self.tool_wrapper.get_wrapped_tools()

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

    def create_crew_member(
        self,
        name: str,
        role: str,
        goal: str,
        identity: Optional[AgentIdentity] = None,
        allowed_tools: Optional[List[str]] = None,
    ) -> AgentShieldCrewMember:
        """Create an AgentShield-managed CrewAI crew member."""
        agent_identity = identity or AgentIdentity(
            agent_id=self.config.agent_id,
            agent_name=name,
            framework=self.framework_type,
            tenant_id=self.config.tenant_id or "default-tenant",
            allowed_tools=allowed_tools or self.config.allowed_tools,
        )
        return AgentShieldCrewMember(
            name=name,
            role=role,
            goal=goal,
            identity=agent_identity,
            tool_wrapper=self.tool_wrapper,
            allowed_tools=allowed_tools,
        )


# Register with global registry
integration_registry.register_adapter_class(IntegrationType.SDK_CREWAI, CrewAIIntegrationAdapter)
