"""
AgentShield AI — Controlled Execution Gateway (Phase 6).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.execution import ExecutionRequest, ToolExecutionResponse
from agentshield.database.models.agent import Agent
from agentshield.services.execution_service import ExecutionService


class ExecutionGateway:
    """Server-side execution gateway enforcing mandatory authorization for protected tool calls."""

    @classmethod
    async def process_execution(
        cls,
        session: AsyncSession,
        user_id: str,
        agent: Agent,
        request: ExecutionRequest,
    ) -> ToolExecutionResponse:
        service = ExecutionService(session)
        return await service.execute_request(user_id=user_id, agent=agent, request=request)
