"""
AgentShield AI — Dashboard Service.

Calculates aggregated security metrics from real database records for the
authenticated user.
"""

from __future__ import annotations

from datetime import datetime, time, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.database.models.activity import ActivityEvent
from agentshield.database.models.agent import Agent
from agentshield.database.models.approval import ApprovalRequest
from agentshield.database.models.threat import ThreatEvent
from agentshield.services.schemas import DashboardSummary


class DashboardService:
    """Computes real metrics strictly scoped to user_id."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_summary(self, user_id: str) -> DashboardSummary:
        # Total and active agents
        stmt_agents = select(
            func.count(Agent.id).label("total"),
            func.count(Agent.id).filter(Agent.status == "active").label("active"),
        ).where(Agent.owner_user_id == user_id)
        agents_res = (await self.session.execute(stmt_agents)).one()
        total_agents = agents_res.total or 0
        active_agents = agents_res.active or 0

        # Activity stats
        now = datetime.now(timezone.utc)
        today_start = datetime.combine(now.date(), time.min, tzinfo=timezone.utc)

        stmt_act = select(
            func.count(ActivityEvent.id).label("total"),
            func.count(ActivityEvent.id).filter(ActivityEvent.created_at >= today_start).label("today"),
            func.count(ActivityEvent.id).filter(
                ActivityEvent.created_at >= today_start,
                ActivityEvent.decision == "BLOCK",
            ).label("blocked_today"),
        ).where(ActivityEvent.user_id == user_id)
        act_res = (await self.session.execute(stmt_act)).one()
        total_activities = act_res.total or 0
        actions_today = act_res.today or 0
        blocked_actions = act_res.blocked_today or 0

        # Pending approvals
        stmt_app = select(func.count(ApprovalRequest.id)).where(
            ApprovalRequest.user_id == user_id,
            ApprovalRequest.status == "pending",
        )
        pending_approvals = (await self.session.execute(stmt_app)).scalar() or 0

        # Threats by severity
        stmt_threats = select(
            ThreatEvent.severity,
            func.count(ThreatEvent.id),
        ).where(
            ThreatEvent.user_id == user_id,
        ).group_by(ThreatEvent.severity)
        threat_rows = (await self.session.execute(stmt_threats)).all()

        threats_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        threats_total = 0
        for sev, count in threat_rows:
            key = str(sev).lower()
            if key in threats_by_severity:
                threats_by_severity[key] = count
            else:
                threats_by_severity[key] = count
            threats_total += count

        return DashboardSummary(
            total_agents=total_agents,
            active_agents=active_agents,
            total_activities=total_activities,
            actions_today=actions_today,
            blocked_actions=blocked_actions,
            pending_approvals=pending_approvals,
            threats_total=threats_total,
            threats_by_severity=threats_by_severity,
        )
