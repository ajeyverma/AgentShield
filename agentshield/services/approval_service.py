"""
AgentShield AI — Approval Service.
"""

from __future__ import annotations

import math
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import ApprovalNotFoundError, AuthorizationError
from agentshield.database.models.approval import ApprovalRequest
from agentshield.services.schemas import (
    ApprovalCreate,
    ApprovalResponse,
    ApprovalUpdate,
    PaginatedResponse,
)


class ApprovalService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_approvals(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        status: str | None = None,
    ) -> PaginatedResponse[ApprovalResponse]:
        query = select(ApprovalRequest).where(ApprovalRequest.user_id == user_id)
        count_query = select(func.count(ApprovalRequest.id)).where(ApprovalRequest.user_id == user_id)

        if status:
            query = query.where(ApprovalRequest.status == status.lower())
            count_query = count_query.where(ApprovalRequest.status == status.lower())

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(ApprovalRequest.created_at.desc()).offset(offset).limit(size)
        items = (await self.session.execute(query)).scalars().all()

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(
            items=[ApprovalResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def get_by_id(self, approval_id: str, user_id: str) -> ApprovalResponse | None:
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        res = (await self.session.execute(stmt)).scalar_one_or_none()
        return ApprovalResponse.model_validate(res) if res else None

    async def update_status(self, approval_id: str, user_id: str, data: ApprovalUpdate) -> ApprovalResponse:
        """Update approval status (persisted record only; no tool execution in Phase 3)."""
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        approval = (await self.session.execute(stmt)).scalar_one_or_none()
        if not approval:
            raise ApprovalNotFoundError(f"Approval request '{approval_id}' not found.")

        approval.status = data.status.lower()
        await self.session.flush()
        await self.session.refresh(approval)
        await self.session.commit()
        return ApprovalResponse.model_validate(approval)

    async def create_approval_request(self, user_id: str, data: ApprovalCreate) -> ApprovalResponse:
        approval = ApprovalRequest(
            user_id=user_id,
            agent_id=data.agent_id,
            request_id=data.request_id,
            tool_name=data.tool_name,
            operation=data.operation,
            risk_level=data.risk_level.upper(),
            description=data.description,
            status="pending",
            expires_at=data.expires_at,
        )
        self.session.add(approval)
        await self.session.flush()
        await self.session.refresh(approval)
        await self.session.commit()
        return ApprovalResponse.model_validate(approval)
