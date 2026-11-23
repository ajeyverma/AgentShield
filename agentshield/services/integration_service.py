"""
AgentShield AI — Integration Service.
"""

from __future__ import annotations

import math
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.core.exceptions import AuthorizationError
from agentshield.database.models.integration import Integration
from agentshield.services.schemas import (
    IntegrationCreate,
    IntegrationResponse,
    IntegrationUpdate,
    PaginatedResponse,
)


class IntegrationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_integrations(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
    ) -> PaginatedResponse[IntegrationResponse]:
        query = select(Integration).where(Integration.user_id == user_id)
        count_query = select(func.count(Integration.id)).where(Integration.user_id == user_id)

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(Integration.created_at.desc()).offset(offset).limit(size)
        items = (await self.session.execute(query)).scalars().all()

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(
            items=[IntegrationResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def create_integration(self, user_id: str, data: IntegrationCreate) -> IntegrationResponse:
        integration = Integration(
            user_id=user_id,
            integration_name=data.integration_name.strip(),
            integration_type=data.integration_type.strip(),
            status=data.status,
            configuration_metadata=data.configuration_metadata,
        )
        self.session.add(integration)
        await self.session.flush()
        await self.session.refresh(integration)
        await self.session.commit()
        return IntegrationResponse.model_validate(integration)

    async def update_integration(
        self,
        integration_id: str,
        user_id: str,
        data: IntegrationUpdate,
    ) -> IntegrationResponse:
        stmt = select(Integration).where(
            Integration.id == integration_id,
            Integration.user_id == user_id,
        )
        integration = (await self.session.execute(stmt)).scalar_one_or_none()
        if not integration:
            raise AuthorizationError("Integration not found or access denied.")

        if data.integration_name is not None:
            integration.integration_name = data.integration_name.strip()
        if data.status is not None:
            integration.status = data.status
        if data.configuration_metadata is not None:
            integration.configuration_metadata = data.configuration_metadata

        await self.session.flush()
        await self.session.refresh(integration)
        await self.session.commit()
        return IntegrationResponse.model_validate(integration)

    async def delete_integration(self, integration_id: str, user_id: str) -> None:
        stmt = select(Integration).where(
            Integration.id == integration_id,
            Integration.user_id == user_id,
        )
        integration = (await self.session.execute(stmt)).scalar_one_or_none()
        if not integration:
            raise AuthorizationError("Integration not found or access denied.")
        await self.session.delete(integration)
        await self.session.commit()
