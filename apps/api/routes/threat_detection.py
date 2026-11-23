"""
AgentShield AI — Threat Detection API Routes (Phase 5).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from agentshield.contracts.threat import ThreatAnalysisResult
from agentshield.core.exceptions import AuthorizationError
from agentshield.database.models.agent import Agent
from agentshield.identity.service import AgentService
from agentshield.realtime.event_broadcaster import broadcaster
from agentshield.services.schemas import PaginatedResponse
from agentshield.services.threat_service import ThreatService
from agentshield.threat_detection.engine import default_registry, threat_coordinator
from agentshield.threat_detection.schemas import (
    DetectorMetadata,
    ThreatAnalyzeRequest,
    ThreatFindingResponse,
    ThreatFindingUpdate,
    ThreatSummaryResponse,
)
from apps.api.dependencies import CurrentUser, DbSession

router = APIRouter(prefix="/threat-detection", tags=["Threat Detection"])


@router.post("/analyze", response_model=ThreatAnalysisResult)
async def analyze_threats(
    payload: ThreatAnalyzeRequest,
    user: CurrentUser,
    db: DbSession,
) -> ThreatAnalysisResult:
    """Run standalone threat detection analysis across all registered detectors.

    Does not execute actions or generate authorization decisions (Phase 4 authority).
    """
    # Verify agent ownership
    agent_id = str(payload.action_request.agent_id)
    agent_service = AgentService(db)
    try:
        agent = await agent_service.get_agent(agent_id, user.id)
    except AuthorizationError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found or access denied.",
        )

    # Attach user_id
    payload.action_request.user_id = user.id

    # Run threat analysis
    result = threat_coordinator.analyze_action(
        request=payload.action_request,
        provenance=payload.provenance,
        history=payload.relevant_history,
    )

    # Broadcast findings if any
    for tf in result.findings:
        await broadcaster.broadcast_event(
            user.id,
            "threat.finding.created",
            {
                "finding_id": str(tf.finding_id),
                "request_id": str(payload.action_request.request_id),
                "agent_id": agent.id,
                "threat_type": tf.threat_type.value if hasattr(tf.threat_type, "value") else str(tf.threat_type),
                "title": tf.title,
                "severity": tf.severity.value if hasattr(tf.severity, "value") else str(tf.severity),
                "confidence": tf.confidence.value if hasattr(tf.confidence, "value") else str(tf.confidence),
            },
        )

    return result


@router.get("/findings", response_model=PaginatedResponse[ThreatFindingResponse])
async def list_threat_findings(
    user: CurrentUser,
    db: DbSession,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: str | None = None,
    threat_type: str | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
) -> PaginatedResponse[ThreatFindingResponse]:
    """List granular threat findings for the authenticated user."""
    service = ThreatService(db)
    return await service.list_findings(
        user_id=user.id,
        page=page,
        size=size,
        agent_id=agent_id,
        threat_type=threat_type,
        severity=severity,
        status=status_filter,
    )


@router.get("/findings/{finding_id}", response_model=ThreatFindingResponse)
async def get_threat_finding(
    finding_id: str,
    user: CurrentUser,
    db: DbSession,
) -> ThreatFindingResponse:
    """Retrieve detailed information and evidence for a specific threat finding."""
    service = ThreatService(db)
    finding = await service.get_finding_by_id(finding_id, user.id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat finding '{finding_id}' not found.",
        )
    return finding


@router.patch("/findings/{finding_id}", response_model=ThreatFindingResponse)
async def update_threat_finding_status(
    finding_id: str,
    payload: ThreatFindingUpdate,
    user: CurrentUser,
    db: DbSession,
) -> ThreatFindingResponse:
    """Update triage/remediation status for a threat finding (open, investigating, resolved, dismissed)."""
    service = ThreatService(db)
    try:
        updated = await service.update_finding_status(
            finding_id=finding_id,
            user_id=user.id,
            status=payload.status.value,
        )
        await broadcaster.broadcast_event(
            user.id,
            "threat.finding.updated",
            {"finding_id": finding_id, "status": payload.status.value},
        )
        return updated
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc.message),
        ) from exc


@router.get("/summary", response_model=ThreatSummaryResponse)
async def get_threat_summary(
    user: CurrentUser,
    db: DbSession,
) -> ThreatSummaryResponse:
    """Get aggregated threat detection statistics and category distributions."""
    service = ThreatService(db)
    return await service.get_summary(user.id)


@router.get("/detectors", response_model=list[DetectorMetadata])
async def list_registered_detectors(
    user: CurrentUser,
) -> list[DetectorMetadata]:
    """List all registered threat detectors, versions, and operational statuses."""
    detectors = default_registry.list_all()
    return [
        DetectorMetadata(
            detector_id=d.detector_id,
            detector_name=d.detector_name,
            category=d.category.value if hasattr(d.category, "value") else str(d.category),
            version=d.detector_version,
            is_active=d.is_active,
            description=f"{d.detector_name} ({d.detector_id})",
        )
        for d in detectors
    ]
