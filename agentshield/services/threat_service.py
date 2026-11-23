"""
AgentShield AI — Threat Service.
"""

from __future__ import annotations

import math
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import AuthorizationError
from agentshield.database.models.threat import ThreatEvent
from agentshield.services.schemas import PaginatedResponse, ThreatCreate, ThreatResponse, ThreatUpdate


class ThreatService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_threats(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        status: str | None = None,
        severity: str | None = None,
    ) -> PaginatedResponse[ThreatResponse]:
        query = select(ThreatEvent).where(ThreatEvent.user_id == user_id)
        count_query = select(func.count(ThreatEvent.id)).where(ThreatEvent.user_id == user_id)

        if status:
            query = query.where(ThreatEvent.status == status.lower())
            count_query = count_query.where(ThreatEvent.status == status.lower())
        if severity:
            query = query.where(ThreatEvent.severity == severity.upper())
            count_query = count_query.where(ThreatEvent.severity == severity.upper())

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(ThreatEvent.created_at.desc()).offset(offset).limit(size)
        items = (await self.session.execute(query)).scalars().all()

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(
            items=[ThreatResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def get_by_id(self, threat_id: str, user_id: str) -> ThreatResponse | None:
        stmt = select(ThreatEvent).where(
            ThreatEvent.id == threat_id,
            ThreatEvent.user_id == user_id,
        )
        res = (await self.session.execute(stmt)).scalar_one_or_none()
        return ThreatResponse.model_validate(res) if res else None

    async def update_status(self, threat_id: str, user_id: str, data: ThreatUpdate) -> ThreatResponse:
        stmt = select(ThreatEvent).where(
            ThreatEvent.id == threat_id,
            ThreatEvent.user_id == user_id,
        )
        threat = (await self.session.execute(stmt)).scalar_one_or_none()
        if not threat:
            raise AuthorizationError("Threat not found or access denied.")

        threat.status = data.status.lower()
        await self.session.flush()
        await self.session.refresh(threat)
        await self.session.commit()
        return ThreatResponse.model_validate(threat)

    async def record_threat(self, user_id: str, data: ThreatCreate) -> ThreatResponse:
        threat = ThreatEvent(
            user_id=user_id,
            agent_id=data.agent_id,
            threat_type=data.threat_type,
            severity=data.severity.upper(),
            description=data.description,
            status="open",
        )
        self.session.add(threat)
        await self.session.flush()
        await self.session.refresh(threat)
        await self.session.commit()
        return ThreatResponse.model_validate(threat)
