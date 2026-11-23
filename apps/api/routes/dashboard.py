"""
AgentShield AI — Dashboard Routes.
"""

from __future__ import annotations

from fastapi import APIRouter

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.services.dashboard_service import DashboardService
from agentshield.services.schemas import DashboardSummary

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    user: CurrentUser,
    db: DbSession,
) -> DashboardSummary:
    """Retrieve aggregated dashboard metrics calculated from the database for the user."""
    service = DashboardService(db)
    return await service.get_summary(user.id)
