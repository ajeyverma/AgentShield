"""LangGraph ToolNode integration for AgentShield AI.

Implements `AgentShieldToolNode` which can be dropped into any LangGraph
StateGraph. It executes tool calls requested by agent nodes through AgentShield,
capturing security decisions and handling ASK_HUMAN workflow interruptions.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel

from agentshield.integrations.langgraph.tool_wrapper import LangGraphToolWrapper, AgentShieldLangGraphTool
from agentshield.integrations.core.result_handler import AgentShieldToolResult
from agentshield.integrations.core.tool_wrapper import parse_composite_tool_name
from agentshield.contracts.enums import Decision


class ToolCallState(BaseModel):
    """Represents a tool call extracted from state."""
    id: str
    name: str
    args: Dict[str, Any]


class ToolExecutionOutput(BaseModel):
    """Result of executing a tool call through AgentShieldToolNode."""
    tool_call_id: str
    tool_name: str
    decision: str
    output: Any = ""
    is_error: bool = False
    requires_approval: bool = False
    approval_request_id: Optional[str] = None


class AgentShieldToolNode:
    """A LangGraph-compatible node that executes tool calls via AgentShield.

    Can be added as a graph node:
        `builder.add_node("tools", agent_shield_tool_node)`

    Supports both LangChain AIMessage tool_calls and raw dictionary message formats.
    """

    def __init__(
        self,
        tool_wrapper: LangGraphToolWrapper,
        tools: Optional[Sequence[AgentShieldLangGraphTool]] = None,
        interrupt_on_approval: bool = True,
    ):
        self.tool_wrapper = tool_wrapper
        self.interrupt_on_approval = interrupt_on_approval
        
        wrapped = tools if tools is not None else tool_wrapper.get_wrapped_tools()
        self.tools_by_name = {t.name: t for t in wrapped}

    def extract_tool_calls(self, state: Union[Dict[str, Any], Any]) -> List[ToolCallState]:
        tool_calls: List[ToolCallState] = []
        messages: List[Any] = []

        if isinstance(state, dict):
            messages = state.get("messages", [])
        elif hasattr(state, "messages"):
            messages = getattr(state, "messages", [])

        if not messages:
            return tool_calls

        last_message = messages[-1]

        if hasattr(last_message, "tool_calls") and getattr(last_message, "tool_calls"):
            for tc in getattr(last_message, "tool_calls"):
                if isinstance(tc, dict):
                    tool_calls.append(ToolCallState(
                        id=tc.get("id", "call_default"),
                        name=tc.get("name", ""),
                        args=tc.get("args", {}) or {},
                    ))
                elif hasattr(tc, "name"):
                    tool_calls.append(ToolCallState(
                        id=getattr(tc, "id", "call_default"),
                        name=getattr(tc, "name", ""),
                        args=getattr(tc, "args", {}) or {},
                    ))
        elif isinstance(last_message, dict) and "tool_calls" in last_message:
            for tc in last_message["tool_calls"]:
                tool_calls.append(ToolCallState(
                    id=tc.get("id", "call_default"),
                    name=tc.get("function", {}).get("name", tc.get("name", "")),
                    args=json.loads(tc.get("function", {}).get("arguments", "{}")) if isinstance(tc.get("function", {}).get("arguments"), str) else tc.get("args", {}),
                ))

        return tool_calls

    def __call__(self, state: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        tool_calls = self.extract_tool_calls(state)
        tool_messages: List[Dict[str, Any]] = []
        outputs: List[ToolExecutionOutput] = []
        interrupted = False

        for call in tool_calls:
            tname, aname = parse_composite_tool_name(call.name)

            result: AgentShieldToolResult = self.tool_wrapper.route_tool_call(
                tool_name=tname,
                action_name=aname,
                arguments=call.args,
            )

            is_error = result.is_blocked()
            requires_approval = result.is_pending_approval()
            if requires_approval and self.interrupt_on_approval:
                interrupted = True

            out_val = result.to_model_output()
            out_str = json.dumps(out_val) if isinstance(out_val, (dict, list)) else str(out_val)

            out = ToolExecutionOutput(
                tool_call_id=call.id,
                tool_name=call.name,
                decision=result.decision or "ALLOW",
                output=out_str,
                is_error=is_error,
                requires_approval=requires_approval,
                approval_request_id=result.approval_id,
            )
            outputs.append(out)

            tool_msg = {
                "role": "tool",
                "name": call.name,
                "tool_call_id": call.id,
                "content": out_str,
                "status": "error" if is_error else "success",
            }
            tool_messages.append(tool_msg)

        return {
            "messages": tool_messages,
            "agentshield_outputs": [o.model_dump() for o in outputs],
            "agentshield_interrupted": interrupted,
        }
