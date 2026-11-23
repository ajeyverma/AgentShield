"""Google ADK agent implementation with AgentShield security interception."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from agentshield.integrations.google_adk.tool_wrapper import GoogleADKToolWrapper
from agentshield.integrations.core.tool_wrapper import parse_composite_tool_name
from agentshield.integrations.core.result_handler import AgentShieldToolResult


class GoogleTurnResult(BaseModel):
    """Result of a Google ADK turn with intercepted tool execution."""
    user_prompt: str
    function_calls: List[Dict[str, Any]] = []
    function_responses: List[Dict[str, Any]] = []
    text_response: Optional[str] = None
    interrupted_for_approval: bool = False
    security_blocked: bool = False


class AgentShieldGoogleAgent:
    """An agent that handles Google GenAI / Gemini turns while routing all tool calls through AgentShield."""

    def __init__(
        self,
        tool_wrapper: GoogleADKToolWrapper,
        agent_name: str = "GoogleSecureAgent",
        model_name: str = "gemini-2.5-flash",
    ):
        self.tool_wrapper = tool_wrapper
        self.agent_name = agent_name
        self.model_name = model_name

    def process_function_call(
        self,
        call_name: str,
        call_args: Dict[str, Any],
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a function call through AgentShield and return Google function response."""
        tname, aname = parse_composite_tool_name(call_name)

        result: AgentShieldToolResult = self.tool_wrapper.route_tool_call(
            tool_name=tname,
            action_name=aname,
            arguments=call_args,
            approval_id=approval_id,
        )
        return self.tool_wrapper.format_function_response(call_name, result)

    def handle_simulated_turn(
        self,
        prompt: str,
        simulated_calls: List[Dict[str, Any]],
    ) -> GoogleTurnResult:
        """Process a conversation turn with specified function calls through AgentShield."""
        function_responses = []
        blocked = False
        approval = False

        for call in simulated_calls:
            name = call.get("name", "")
            args = call.get("args", {})
            resp = self.process_function_call(name, args)
            function_responses.append(resp)
            content = resp.get("response", {}).get("content", {})
            if content.get("decision") == "BLOCK":
                blocked = True
            if content.get("requires_approval"):
                approval = True

        return GoogleTurnResult(
            user_prompt=prompt,
            function_calls=simulated_calls,
            function_responses=function_responses,
            text_response="Completed turn with AgentShield tool enforcement." if not blocked else "Operation was blocked by AgentShield.",
            interrupted_for_approval=approval,
            security_blocked=blocked,
        )
