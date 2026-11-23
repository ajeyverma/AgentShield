"""LangGraph tool wrapper for AgentShield AI.

Wraps AgentShield execution client into LangGraph / LangChain compatible
tool interfaces. In LangGraph, tools are invoked either via LangChain's
BaseTool interface or standard callables that receive tool call arguments
and return string results.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Type, Union
from pydantic import BaseModel, Field, create_model

from agentshield.integrations.core.tool_wrapper import BaseToolWrapper, CANONICAL_TOOLS
from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.result_handler import AgentShieldToolResult


class AgentShieldLangGraphTool:
    """A callable tool object compatible with LangGraph and LangChain tool interfaces.

    Can be invoked directly: `tool(**kwargs)` or `tool.invoke(input_dict)`.
    Provides `.name`, `.description`, `.args_schema`, and `.args`.
    """

    def __init__(
        self,
        name: str,
        tool_name: str,
        action: str,
        description: str,
        wrapper: "LangGraphToolWrapper",
        parameters_schema: Optional[Dict[str, Any]] = None,
        return_direct: bool = False,
    ):
        self.name = name
        self.tool_name = tool_name
        self.action = action
        self.description = description
        self._wrapper = wrapper
        self.parameters_schema = parameters_schema or {}
        self.return_direct = return_direct
        self.args_schema: Optional[Type[BaseModel]] = self._build_args_schema()

    def _build_args_schema(self) -> Optional[Type[BaseModel]]:
        if not self.parameters_schema or "properties" not in self.parameters_schema:
            return None

        fields: Dict[str, Any] = {}
        properties = self.parameters_schema.get("properties", {})
        required = set(self.parameters_schema.get("required", []))

        type_map = {
            "string": str,
            "integer": int,
            "number": float,
            "boolean": bool,
            "object": dict,
            "array": list,
        }

        for prop_name, prop_meta in properties.items():
            py_type = type_map.get(prop_meta.get("type", "string"), Any)
            desc = prop_meta.get("description", "")
            if prop_name in required:
                fields[prop_name] = (py_type, Field(description=desc))
            else:
                default_val = prop_meta.get("default", None)
                fields[prop_name] = (Optional[py_type], Field(default=default_val, description=desc))

        try:
            return create_model(f"{self.name.capitalize()}Args", **fields)
        except Exception:
            return None

    @property
    def args(self) -> Dict[str, Any]:
        if self.args_schema:
            return self.args_schema.model_json_schema()
        return self.parameters_schema

    def __call__(self, *args: Any, **kwargs: Any) -> str:
        if args and not kwargs and isinstance(args[0], dict):
            kwargs = args[0]
        return self.invoke(kwargs)

    def invoke(self, input_data: Union[Dict[str, Any], str], config: Optional[Dict[str, Any]] = None) -> str:
        if isinstance(input_data, str):
            try:
                arguments = json.loads(input_data)
            except Exception:
                arguments = {"input": input_data}
        elif isinstance(input_data, dict):
            arguments = input_data
        else:
            arguments = {"input": str(input_data)}

        result: AgentShieldToolResult = self._wrapper.route_tool_call(self.tool_name, self.action, arguments)
        return result.to_model_output()

    async def ainvoke(self, input_data: Union[Dict[str, Any], str], config: Optional[Dict[str, Any]] = None) -> str:
        return self.invoke(input_data, config)

    def run(self, tool_input: Union[Dict[str, Any], str], **kwargs: Any) -> str:
        return self.invoke(tool_input)


class LangGraphToolWrapper(BaseToolWrapper):
    """Wrapper that adapts AgentShield execution client into LangGraph tools."""

    def __init__(
        self,
        client: AgentShieldExecutionClient,
        config: AgentShieldIntegrationConfig,
    ) -> None:
        super().__init__(client=client, config=config, framework_name="LangGraph")

    def get_wrapped_tools(self) -> List[AgentShieldLangGraphTool]:
        """Return LangGraph tool objects for all allowed canonical tools and actions."""
        tools: List[AgentShieldLangGraphTool] = []
        for tname in self.config.allowed_tools:
            if tname in CANONICAL_TOOLS:
                tool_def = CANONICAL_TOOLS[tname]
                for action in tool_def["actions"]:
                    tool = AgentShieldLangGraphTool(
                        name=f"{tname}_{action}",
                        tool_name=tname,
                        action=action,
                        description=f"[{tname}] {tool_def['description']} (action: {action})",
                        wrapper=self,
                        parameters_schema=tool_def.get("schema"),
                    )
                    tools.append(tool)
        return tools
