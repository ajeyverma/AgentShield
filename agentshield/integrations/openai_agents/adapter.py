"""
AgentShield AI — OpenAI Agents SDK Adapter Implementation (Phase 7).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import SecurityDecision
from agentshield.contracts.enums import Decision, IntegrationType, ToolCategory
from agentshield.integrations.base import BaseIntegrationAdapter
from agentshield.integrations.openai_agents.schemas import AgentShieldToolResult

logger = logging.getLogger("agentshield.integrations.openai_agents.adapter")


class OpenAIIntegrationAdapter(BaseIntegrationAdapter):
    """Concrete adapter connecting the OpenAI Agents SDK to the AgentShield security core."""

    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.SDK_OPENAI

    async def normalize_request(
        self,
        native_tool_call: Any,
        *,
        tenant_id: str,
        agent_id: str,
        session_id: str | None = None,
    ) -> ActionRequest:
        """Map an OpenAI tool call dictionary/object to an ActionRequest."""
        if isinstance(native_tool_call, dict):
            name = native_tool_call.get("name", "")
            raw_args = native_tool_call.get("arguments", {})
        else:
            name = getattr(native_tool_call, "name", "")
            raw_args = getattr(native_tool_call, "arguments", {})

        # Split composite name (e.g. 'calculator_add' -> 'calculator', 'add')
        parts = name.split("_", 1)
        tool_name = parts[0] if parts else "unknown"
        action_name = parts[1] if len(parts) > 1 else "execute"

        # Map to tool category
        cat_map = {
            "calculator": ToolCategory.API,
            "sandbox_fs": ToolCategory.FILESYSTEM,
            "mock_email": ToolCategory.EXTERNAL_INTEGRATION,
            "mock_http": ToolCategory.NETWORK,
        }
        category = cat_map.get(tool_name, ToolCategory.UNKNOWN)

        return ActionRequest(
            request_id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id) if len(tenant_id) == 36 else uuid.uuid4(),
            agent_id=uuid.UUID(agent_id),
            session_id=uuid.UUID(session_id) if session_id and len(session_id) == 36 else None,
            tool_name=tool_name,
            tool_category=category,
            operation=action_name,
            arguments=raw_args if isinstance(raw_args, dict) else {},
            integration_type=self.integration_type,
        )

    async def handle_decision(
        self,
        decision: SecurityDecision,
        execution_result: Any | None = None,
    ) -> AgentShieldToolResult:
        """Map the authoritative SecurityDecision to a model-friendly response."""
        if decision.decision == Decision.ALLOW:
            return AgentShieldToolResult(
                status="SUCCESS",
                decision="ALLOW",
                execution_id=str(decision.decision_id),
                result=execution_result,
            )
        elif decision.decision == Decision.ASK_HUMAN:
            return AgentShieldToolResult(
                status="PENDING_APPROVAL",
                decision="ASK_HUMAN",
                execution_id=str(decision.decision_id),
                approval_id=str(decision.decision_id),
                message="Action paused pending human approval.",
            )
        else:
            return AgentShieldToolResult(
                status="BLOCKED",
                decision="BLOCK",
                execution_id=str(decision.decision_id),
                error_message=decision.reasons[0] if decision.reasons else "Action blocked by security policy.",
            )
