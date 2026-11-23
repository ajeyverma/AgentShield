"""
AgentShield AI — Audit Log Service.
"""

from __future__ import annotations

import math
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.database.models.audit_log import AuditLog
from agentshield.services.schemas import AuditLogCreate, AuditLogResponse, PaginatedResponse


class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_audit_logs(
        self,
        user_id: str,
        page: int = 1,
        size: int = 50,
        event_type: str | None = None,
    ) -> PaginatedResponse[AuditLogResponse]:
        query = select(AuditLog).where(AuditLog.user_id == user_id)
        count_query = select(func.count(AuditLog.id)).where(AuditLog.user_id == user_id)

        if event_type:
            query = query.where(AuditLog.event_type == event_type)
            count_query = count_query.where(AuditLog.event_type == event_type)

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(size)
        items = (await self.session.execute(query)).scalars().all()

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(
            items=[AuditLogResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def get_by_id(self, log_id: str, user_id: str) -> AuditLogResponse | None:
        stmt = select(AuditLog).where(
            AuditLog.id == log_id,
            AuditLog.user_id == user_id,
        )
        res = (await self.session.execute(stmt)).scalar_one_or_none()
        return AuditLogResponse.model_validate(res) if res else None

    async def record_log(self, user_id: str, data: AuditLogCreate) -> AuditLogResponse:
        log = AuditLog(
            user_id=user_id,
            agent_id=data.agent_id,
            event_type=data.event_type,
            resource_type=data.resource_type,
            resource_id=data.resource_id,
            description=data.description,
        )
        self.session.add(log)
        await self.session.flush()
        await self.session.refresh(log)
        await self.session.commit()
        return AuditLogResponse.model_validate(log)
