"""LangGraph integration adapter for AgentShield AI."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.base_adapter import BaseFrameworkAdapter
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.integration_registry import integration_registry
from agentshield.integrations.core.result_handler import AgentShieldToolResult
from agentshield.integrations.langgraph.tool_wrapper import LangGraphToolWrapper, AgentShieldLangGraphTool
from agentshield.integrations.langgraph.node import AgentShieldToolNode


class LangGraphIntegrationAdapter(BaseFrameworkAdapter):
    """Adapter for integrating LangGraph agents and state graphs with AgentShield."""

    def __init__(self, config: AgentShieldIntegrationConfig) -> None:
        super().__init__(config)
        self.tool_wrapper = LangGraphToolWrapper(self.client, self.config)

    @property
    def framework_type(self) -> IntegrationType:
        return IntegrationType.SDK_LANGGRAPH

    @property
    def framework_name(self) -> str:
        return "LangGraph"

    def get_wrapped_tools(self) -> List[AgentShieldLangGraphTool]:
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

    def create_tool_node(
        self,
        interrupt_on_approval: bool = True,
    ) -> AgentShieldToolNode:
        """Create an AgentShieldToolNode for state graphs."""
        return AgentShieldToolNode(tool_wrapper=self.tool_wrapper, interrupt_on_approval=interrupt_on_approval)


# Register with global registry
integration_registry.register_adapter_class(IntegrationType.SDK_LANGGRAPH, LangGraphIntegrationAdapter)
