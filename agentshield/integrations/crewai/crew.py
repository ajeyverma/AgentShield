"""CrewAI multi-agent hierarchy and delegation guard for AgentShield AI."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from agentshield.integrations.core.agent_identity import AgentIdentity
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.crewai.tool_wrapper import CrewAIToolWrapper, AgentShieldCrewTool


class AgentShieldCrewMember:
    """Represents a CrewAI agent member wrapped with AgentShield security controls."""

    def __init__(
        self,
        name: str,
        role: str,
        goal: str,
        identity: AgentIdentity,
        tool_wrapper: CrewAIToolWrapper,
        allowed_tools: Optional[List[str]] = None,
    ):
        self.name = name
        self.role = role
        self.goal = goal
        self.identity = identity
        self.tool_wrapper = tool_wrapper
        self.allowed_tools = allowed_tools or tool_wrapper.config.allowed_tools

    @property
    def tools(self) -> List[AgentShieldCrewTool]:
        all_tools = self.tool_wrapper.get_wrapped_tools()
        # Filter down by allowed tools
        return [t for t in all_tools if any(t.name.startswith(at) for at in self.allowed_tools)]

    def delegate_to(
        self,
        sub_agent_name: str,
        sub_agent_role: str,
        restricted_tools: Optional[List[str]] = None,
    ) -> "AgentShieldCrewMember":
        """Safely spawn a delegated sub-agent with restricted privileges."""
        sub_identity = self.identity.derive_delegated_identity(
            delegated_name=sub_agent_name,
            tool_scopes=restricted_tools,
        )
        # Ensure sub-agent tools cannot exceed parent's allowed tools
        parent_allowed = set(self.allowed_tools)
        if restricted_tools:
            delegated_allowed = [t for t in restricted_tools if t in parent_allowed]
        else:
            delegated_allowed = list(parent_allowed)

        # Clone config with restricted tools
        sub_config = self.tool_wrapper.config.model_copy(update={
            "agent_id": sub_identity.agent_id,
            "allowed_tools": delegated_allowed,
        })
        from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
        sub_client = AgentShieldExecutionClient(sub_config)
        sub_wrapper = CrewAIToolWrapper(sub_client, sub_config)

        return AgentShieldCrewMember(
            name=sub_agent_name,
            role=sub_agent_role,
            goal=f"Delegated from {self.name}",
            identity=sub_identity,
            tool_wrapper=sub_wrapper,
            allowed_tools=delegated_allowed,
        )
