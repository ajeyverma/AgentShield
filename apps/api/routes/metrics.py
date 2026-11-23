"""
AgentShield AI — Metrics & Health Routes (Phase 11).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from sqlalchemy import text

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.core.config import settings
from agentshield.observability.metrics import metrics_collector
from agentshield.services.schemas import MetricsSummaryResponse, SystemHealthResponse
from agentshield.services.tamper_evident_audit import TamperEvidentAuditService

router = APIRouter(prefix="/metrics", tags=["Metrics & Observability"])


@router.get("/summary", response_model=MetricsSummaryResponse)
async def get_metrics_summary(
    user: CurrentUser,
) -> MetricsSummaryResponse:
    """Return aggregated counters, gauges, and latency percentiles."""
    summary = metrics_collector.get_metrics_summary()
    return MetricsSummaryResponse(
        counters=summary.get("counters", {}),
        gauges=summary.get("gauges", {}),
        latency_percentiles=summary.get("latency_percentiles", {}),
        collected_at=datetime.now(UTC),
    )


@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health(
    user: CurrentUser,
    db: DbSession,
) -> SystemHealthResponse:
    """Verify runtime health, database responsiveness, and audit chain integrity."""
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    audit_svc = TamperEvidentAuditService(db)
    audit_res = await audit_svc.verify_chain(tenant_id=user.id)

    metrics = metrics_collector.get_metrics_summary()

    overall_status = "healthy" if (db_ok and audit_res.is_valid) else "degraded"

    return SystemHealthResponse(
        status=overall_status,
        database_connected=db_ok,
        version=settings.app_version,
        audit_chain_valid=audit_res.is_valid,
        metrics_summary={
            "requests_total": metrics.get("counters", {}).get("security.requests.total", 0),
            "decisions_allow": metrics.get("counters", {}).get("security.decisions.ALLOW", 0),
            "decisions_block": metrics.get("counters", {}).get("security.decisions.BLOCK", 0),
            "decisions_ask_human": metrics.get("counters", {}).get("security.decisions.ASK_HUMAN", 0),
            "active_alerts": metrics.get("gauges", {}).get("security.alerts.active", 0),
        },
    )
