"""
AgentShield AI — Activity Service.
"""

from __future__ import annotations

import math
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.database.models.activity import ActivityEvent
from agentshield.services.schemas import ActivityCreate, ActivityResponse, PaginatedResponse


class ActivityService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_activity(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        agent_id: str | None = None,
        decision: str | None = None,
        risk_level: str | None = None,
    ) -> PaginatedResponse[ActivityResponse]:
        query = select(ActivityEvent).where(ActivityEvent.user_id == user_id)
        count_query = select(func.count(ActivityEvent.id)).where(ActivityEvent.user_id == user_id)

        if agent_id:
            query = query.where(ActivityEvent.agent_id == agent_id)
            count_query = count_query.where(ActivityEvent.agent_id == agent_id)
        if decision:
            query = query.where(ActivityEvent.decision == decision.upper())
            count_query = count_query.where(ActivityEvent.decision == decision.upper())
        if risk_level:
            query = query.where(ActivityEvent.risk_level == risk_level.upper())
            count_query = count_query.where(ActivityEvent.risk_level == risk_level.upper())

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(ActivityEvent.created_at.desc()).offset(offset).limit(size)
        items = (await self.session.execute(query)).scalars().all()

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(
            items=[ActivityResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def get_by_id(self, event_id: str, user_id: str) -> ActivityResponse | None:
        stmt = select(ActivityEvent).where(
            ActivityEvent.id == event_id,
            ActivityEvent.user_id == user_id,
        )
        res = (await self.session.execute(stmt)).scalar_one_or_none()
        return ActivityResponse.model_validate(res) if res else None

    async def record_activity(self, user_id: str, data: ActivityCreate) -> ActivityResponse:
        event = ActivityEvent(
            request_id=data.request_id,
            user_id=user_id,
            agent_id=data.agent_id,
            tool_name=data.tool_name,
            operation=data.operation,
            decision=data.decision.upper(),
            risk_level=data.risk_level.upper(),
            execution_status=data.execution_status,
            arguments_summary=data.arguments_summary,
        )
        self.session.add(event)
        await self.session.flush()
        await self.session.refresh(event)
        await self.session.commit()
        return ActivityResponse.model_validate(event)
