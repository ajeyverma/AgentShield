"""
AgentShield AI — MCP Policy Adapter (Phase 8).
"""

from __future__ import annotations

import uuid
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.contracts.execution import compute_canonical_argument_hash


class MCPPolicyAdapter:
    """
    Adapts MCP protocol requests (tools/call, resources/read, prompts/get)
    into standard AgentShield ActionRequest contracts for Phase 4 & 5 security evaluation.
    """

    @classmethod
    def infer_category(cls, tool_name: str, arguments: dict[str, Any]) -> ToolCategory:
        """Infer ToolCategory based on MCP operation/tool name heuristics."""
        name_lower = tool_name.lower()
        if any(kw in name_lower for kw in ("bash", "cmd", "shell", "exec", "terminal", "powershell", "run")):
            return ToolCategory.TERMINAL
        if any(kw in name_lower for kw in ("file", "read", "write", "fs", "dir", "path", "folder")):
            return ToolCategory.FILE_SYSTEM
        if any(kw in name_lower for kw in ("http", "curl", "fetch", "request", "api", "url", "web", "download")):
            return ToolCategory.NETWORK
        if any(kw in name_lower for kw in ("db", "sql", "query", "database", "postgres", "mysql", "sqlite")):
            return ToolCategory.DATABASE
        if any(kw in name_lower for kw in ("email", "mail", "send_email", "smtp")):
            return ToolCategory.EMAIL
        return ToolCategory.UNKNOWN

    @classmethod
    def create_action_request(
        cls,
        user_id: str,
        agent_id: str,
        method: str,
        params: dict[str, Any],
        request_id: str | None = None,
    ) -> ActionRequest:
        """
        Create a normalized ActionRequest from MCP method and params.
        """
        req_id = uuid.UUID(request_id) if request_id else uuid.uuid4()
        tenant_uuid = uuid.UUID(user_id) if isinstance(user_id, str) and len(user_id) == 36 else uuid.uuid4()
        agent_uuid = uuid.UUID(agent_id) if isinstance(agent_id, str) and len(agent_id) == 36 else uuid.uuid4()
        user_uuid = tenant_uuid

        if method == "tools/call":
            tool_name = params.get("name", "unknown_tool")
            arguments = params.get("arguments") or {}
            category = cls.infer_category(tool_name, arguments)
            target = str(arguments.get("path") or arguments.get("url") or arguments.get("target") or tool_name)
            return ActionRequest(
                request_id=req_id,
                tenant_id=tenant_uuid,
                agent_id=agent_uuid,
                user_id=user_uuid,
                tool_name=tool_name,
                operation="tools/call",
                tool_category=category,
                integration_type=IntegrationType.MCP,
                arguments=arguments,
                target_resource=target,
            )

        elif method == "resources/read":
            uri = params.get("uri", "")
            return ActionRequest(
                request_id=req_id,
                tenant_id=tenant_uuid,
                agent_id=agent_uuid,
                user_id=user_uuid,
                tool_name="resources/read",
                operation="resources/read",
                tool_category=ToolCategory.FILE_SYSTEM,
                integration_type=IntegrationType.MCP,
                arguments={"uri": uri},
                target_resource=uri,
            )

        elif method == "prompts/get":
            prompt_name = params.get("name", "unknown_prompt")
            arguments = params.get("arguments") or {}
            return ActionRequest(
                request_id=req_id,
                tenant_id=tenant_uuid,
                agent_id=agent_uuid,
                user_id=user_uuid,
                tool_name=f"prompts/{prompt_name}",
                operation="prompts/get",
                tool_category=ToolCategory.UNKNOWN,
                integration_type=IntegrationType.MCP,
                arguments=arguments,
                target_resource=prompt_name,
            )

        else:
            return ActionRequest(
                request_id=req_id,
                tenant_id=tenant_uuid,
                agent_id=agent_uuid,
                user_id=user_uuid,
                tool_name=method,
                operation=method,
                tool_category=ToolCategory.UNKNOWN,
                integration_type=IntegrationType.MCP,
                arguments=params,
                target_resource=method,
            )

    @classmethod
    def get_argument_hash(cls, arguments: dict[str, Any]) -> str:
        """Compute SHA-256 canonical hash of arguments."""
        return compute_canonical_argument_hash(arguments)
