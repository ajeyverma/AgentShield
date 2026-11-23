"""Google Agent Development Kit (Google ADK) tool wrapper for AgentShield AI.

Generates Google GenAI / ADK compatible tool declarations and function callers.
Supports both `google.genai.types` if available and standard JSON schema
function declarations compatible with Gemini model tool calling.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional
from agentshield.integrations.core.tool_wrapper import BaseToolWrapper, CANONICAL_TOOLS
from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.result_handler import AgentShieldToolResult

try:
    from google.genai import types as genai_types
    _GENAI_TYPES_AVAILABLE = True
except ImportError:
    _GENAI_TYPES_AVAILABLE = False


class GoogleADKToolWrapper(BaseToolWrapper):
    """Wrapper that formats AgentShield tools for Google ADK / Gemini."""

    def __init__(
        self,
        client: AgentShieldExecutionClient,
        config: AgentShieldIntegrationConfig,
    ) -> None:
        super().__init__(client=client, config=config, framework_name="GoogleADK")

    def get_function_declarations(self) -> List[Dict[str, Any]]:
        """Return function declarations for all allowed canonical tools and actions."""
        declarations: List[Dict[str, Any]] = []
        for tname in self.config.allowed_tools:
            if tname in CANONICAL_TOOLS:
                tool_def = CANONICAL_TOOLS[tname]
                for action in tool_def["actions"]:
                    declarations.append({
                        "name": f"{tname}_{action}",
                        "description": f"[{tname}] {tool_def['description']} (action: {action})",
                        "parameters": tool_def.get("schema", {"type": "object", "properties": {}}),
                    })
        return declarations

    def get_genai_tool(self) -> Any:
        declarations = self.get_function_declarations()
        if _GENAI_TYPES_AVAILABLE:
            try:
                func_decls = []
                for d in declarations:
                    func_decls.append(
                        genai_types.FunctionDeclaration(
                            name=d["name"],
                            description=d["description"],
                            parameters=d.get("parameters"),
                        )
                    )
                return genai_types.Tool(function_declarations=func_decls)
            except Exception:
                pass
        return {"function_declarations": declarations}

    def format_function_response(
        self,
        tool_call_name: str,
        result: AgentShieldToolResult,
    ) -> Dict[str, Any]:
        """Format an AgentShieldToolResult as a Google Gemini function_response."""
        return {
            "name": tool_call_name,
            "response": {
                "name": tool_call_name,
                "content": {
                    "decision": result.decision or "ALLOW",
                    "output": result.to_model_output(),
                    "success": result.is_allowed(),
                    "requires_approval": result.is_pending_approval(),
                    "approval_id": result.approval_id,
                },
            },
        }
