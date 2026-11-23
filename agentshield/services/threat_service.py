"""
AgentShield AI — Threat Service (Phase 5).

Manages persistence, retrieval, status updates, and summary metrics for both
ThreatEvents and granular ThreatFindings.
"""

from __future__ import annotations

import json
import math
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.threat import ThreatFinding
from agentshield.core.exceptions import AuthorizationError
from agentshield.database.models.threat import ThreatEvent
from agentshield.database.models.threat_finding import ThreatFindingModel
from agentshield.services.schemas import (
    PaginatedResponse,
    ThreatCreate,
    ThreatResponse,
    ThreatUpdate,
)
from agentshield.threat_detection.schemas import (
    ThreatFindingResponse,
    ThreatSummaryResponse,
)


class ThreatService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ── Legacy / Event Methods (Phase 3 compatible) ─────────────────────────

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

    # ── Phase 5 Granular Threat Finding Methods ─────────────────────────────

    async def record_finding(self, user_id: str, finding: ThreatFinding) -> ThreatFindingResponse:
        """Persist a single ThreatFinding to the database."""
        model = ThreatFindingModel(
            id=str(finding.finding_id),
            request_id=str(finding.request_id),
            user_id=user_id,
            agent_id=str(finding.agent_id),
            detector_id=finding.detector_id,
            threat_type=finding.threat_type.value if hasattr(finding.threat_type, "value") else str(finding.threat_type),
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            confidence=finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
            risk_contribution=finding.risk_contribution,
            evidence_json=json.dumps(finding.evidence) if finding.evidence else None,
            affected_resource=finding.affected_resource,
            recommended_action=finding.recommended_action,
            status=finding.status.value if hasattr(finding.status, "value") else str(finding.status),
            detector_version=finding.detector_version,
        )
        self.session.add(model)
        await self.session.flush()
        await self.session.refresh(model)
        await self.session.commit()
        return self._to_finding_response(model)

    async def list_findings(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        agent_id: str | None = None,
        threat_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> PaginatedResponse[ThreatFindingResponse]:
        query = select(ThreatFindingModel).where(ThreatFindingModel.user_id == user_id)
        count_q = select(func.count(ThreatFindingModel.id)).where(ThreatFindingModel.user_id == user_id)

        if agent_id:
            query = query.where(ThreatFindingModel.agent_id == agent_id)
            count_q = count_q.where(ThreatFindingModel.agent_id == agent_id)
        if threat_type:
            query = query.where(ThreatFindingModel.threat_type == threat_type)
            count_q = count_q.where(ThreatFindingModel.threat_type == threat_type)
        if severity:
            query = query.where(ThreatFindingModel.severity == severity.upper())
            count_q = count_q.where(ThreatFindingModel.severity == severity.upper())
        if status:
            query = query.where(ThreatFindingModel.status == status.lower())
            count_q = count_q.where(ThreatFindingModel.status == status.lower())

        total = (await self.session.execute(count_q)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(ThreatFindingModel.created_at.desc()).offset(offset).limit(size)
        rows = (await self.session.execute(query)).scalars().all()

        items = [self._to_finding_response(r) for r in rows]
        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)

    async def get_finding_by_id(self, finding_id: str, user_id: str) -> ThreatFindingResponse | None:
        stmt = select(ThreatFindingModel).where(
            ThreatFindingModel.id == finding_id,
            ThreatFindingModel.user_id == user_id,
        )
        r = (await self.session.execute(stmt)).scalar_one_or_none()
        return self._to_finding_response(r) if r else None

    async def update_finding_status(self, finding_id: str, user_id: str, status: str) -> ThreatFindingResponse:
        stmt = select(ThreatFindingModel).where(
            ThreatFindingModel.id == finding_id,
            ThreatFindingModel.user_id == user_id,
        )
        finding = (await self.session.execute(stmt)).scalar_one_or_none()
        if not finding:
            raise AuthorizationError("Threat finding not found or access denied.")

        finding.status = status.lower()
        await self.session.flush()
        await self.session.refresh(finding)
        await self.session.commit()
        return self._to_finding_response(finding)

    async def get_summary(self, user_id: str) -> ThreatSummaryResponse:
        """Calculate high-level threat findings statistics."""
        # Total count
        total = (await self.session.execute(
            select(func.count(ThreatFindingModel.id)).where(ThreatFindingModel.user_id == user_id)
        )).scalar() or 0

        # Counts by severity
        crit = (await self.session.execute(
            select(func.count(ThreatFindingModel.id)).where(
                ThreatFindingModel.user_id == user_id,
                ThreatFindingModel.severity == "CRITICAL",
            )
        )).scalar() or 0

        high = (await self.session.execute(
            select(func.count(ThreatFindingModel.id)).where(
                ThreatFindingModel.user_id == user_id,
                ThreatFindingModel.severity == "HIGH",
            )
        )).scalar() or 0

        med = (await self.session.execute(
            select(func.count(ThreatFindingModel.id)).where(
                ThreatFindingModel.user_id == user_id,
                ThreatFindingModel.severity == "MEDIUM",
            )
        )).scalar() or 0

        low = (await self.session.execute(
            select(func.count(ThreatFindingModel.id)).where(
                ThreatFindingModel.user_id == user_id,
                ThreatFindingModel.severity == "LOW",
            )
        )).scalar() or 0

        open_cnt = (await self.session.execute(
            select(func.count(ThreatFindingModel.id)).where(
                ThreatFindingModel.user_id == user_id,
                ThreatFindingModel.status == "open",
            )
        )).scalar() or 0

        # Distribution by threat_type
        dist_stmt = select(
            ThreatFindingModel.threat_type,
            func.count(ThreatFindingModel.id),
        ).where(ThreatFindingModel.user_id == user_id).group_by(ThreatFindingModel.threat_type)
        dist_rows = (await self.session.execute(dist_stmt)).all()
        distribution = {row[0]: row[1] for row in dist_rows}

        # 5 most recent findings
        rec_stmt = select(ThreatFindingModel).where(
            ThreatFindingModel.user_id == user_id
        ).order_by(ThreatFindingModel.created_at.desc()).limit(5)
        rec_rows = (await self.session.execute(rec_stmt)).scalars().all()
        recent = [self._to_finding_response(r) for r in rec_rows]

        return ThreatSummaryResponse(
            total_findings=total,
            critical_findings=crit,
            high_findings=high,
            medium_findings=med,
            low_findings=low,
            open_findings=open_cnt,
            category_distribution=distribution,
            recent_findings=recent,
        )

    @staticmethod
    def _to_finding_response(model: ThreatFindingModel) -> ThreatFindingResponse:
        evidence = json.loads(model.evidence_json) if model.evidence_json else {}
        return ThreatFindingResponse(
            id=model.id,
            request_id=model.request_id,
            user_id=model.user_id,
            agent_id=model.agent_id,
            detector_id=model.detector_id,
            threat_type=model.threat_type,
            title=model.title,
            description=model.description,
            severity=model.severity,
            confidence=model.confidence,
            risk_contribution=model.risk_contribution,
            evidence=evidence,
            affected_resource=model.affected_resource,
            recommended_action=model.recommended_action,
            status=model.status,
            detector_version=model.detector_version,
            created_at=model.created_at,
        )
