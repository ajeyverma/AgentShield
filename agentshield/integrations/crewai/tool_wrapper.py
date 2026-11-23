"""CrewAI tool wrapper for AgentShield AI.

Implements CrewAI-compatible tool classes (`AgentShieldCrewTool`).
All tool executions route strictly through AgentShield, carrying full
agent identity metadata and multi-agent delegation context.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentshield.integrations.core.tool_wrapper import BaseToolWrapper, CANONICAL_TOOLS
from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.result_handler import AgentShieldToolResult


class AgentShieldCrewTool:
    """A tool compatible with CrewAI agents and tasks.

    Provides `name`, `description`, `_run(**kwargs)`, and `run(**kwargs)`.
    """

    def __init__(
        self,
        name: str,
        tool_name: str,
        action: str,
        description: str,
        wrapper: "CrewAIToolWrapper",
        parameters_schema: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.tool_name = tool_name
        self.action = action
        self.description = description
        self._wrapper = wrapper
        self.parameters_schema = parameters_schema or {}

    def _run(self, *args: Any, **kwargs: Any) -> str:
        arguments: Dict[str, Any] = {}
        if args and isinstance(args[0], dict):
            arguments.update(args[0])
        elif args and len(args) == 1 and not kwargs:
            arguments["input"] = args[0]
        arguments.update(kwargs)

        result: AgentShieldToolResult = self._wrapper.route_tool_call(self.tool_name, self.action, arguments)
        return result.to_model_output()

    def run(self, *args: Any, **kwargs: Any) -> str:
        return self._run(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> str:
        return self._run(*args, **kwargs)


class CrewAIToolWrapper(BaseToolWrapper):
    """Wrapper that generates CrewAI-compatible tools."""

    def __init__(
        self,
        client: AgentShieldExecutionClient,
        config: AgentShieldIntegrationConfig,
    ) -> None:
        super().__init__(client=client, config=config, framework_name="CrewAI")

    def get_wrapped_tools(self) -> List[AgentShieldCrewTool]:
        """Return CrewAI tool objects for all allowed canonical tools and actions."""
        tools: List[AgentShieldCrewTool] = []
        for tname in self.config.allowed_tools:
            if tname in CANONICAL_TOOLS:
                tool_def = CANONICAL_TOOLS[tname]
                for action in tool_def["actions"]:
                    tool = AgentShieldCrewTool(
                        name=f"{tname}_{action}",
                        tool_name=tname,
                        action=action,
                        description=f"[{tname}] {tool_def['description']} (action: {action})",
                        wrapper=self,
                        parameters_schema=tool_def.get("schema"),
                    )
                    tools.append(tool)
        return tools
