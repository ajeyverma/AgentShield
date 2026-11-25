"""
AgentShield AI — Security Service (Phase 4).

Coordinates action request evaluation, decision persistence, approval request creation,
activity logging, and real-time WebSocket event broadcasting.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import SecurityDecision
from agentshield.contracts.enums import Decision
from agentshield.database.models.activity import ActivityEvent
from agentshield.database.models.agent import Agent
from agentshield.database.models.approval import ApprovalRequest
from agentshield.database.models.policy import Policy
from agentshield.database.models.security_decision import SecurityDecisionModel
from agentshield.database.models.threat_finding import ThreatFindingModel
from agentshield.realtime.event_broadcaster import broadcaster
from agentshield.security.engine import compute_canonical_request_hash, security_engine
from agentshield.services.schemas import PaginatedResponse
from agentshield.services.tamper_evident_audit import TamperEvidentAuditService
from agentshield.threat_detection.engine import threat_coordinator

logger = logging.getLogger("agentshield.services.security")


class SecurityService:
    """Service layer managing security evaluation and decision persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def evaluate_and_record(
        self,
        user_id: str,
        agent: Agent,
        request: ActionRequest,
    ) -> SecurityDecision:
        """Run security evaluation on request, persist the decision and audit, and broadcast real-time events."""
        # 1. Fetch active policies for user
        stmt_policies = select(Policy).where(
            Policy.user_id == user_id,
            Policy.is_enabled == True,  # noqa: E712
        )
        db_policies = (await self.session.execute(stmt_policies)).scalars().all()

        # 2. Fetch recent activity history for behavioral analysis
        stmt_history = select(ActivityEvent).where(
            ActivityEvent.user_id == user_id,
            ActivityEvent.agent_id == agent.id,
        ).order_by(ActivityEvent.created_at.desc()).limit(30)
        history_rows = (await self.session.execute(stmt_history)).scalars().all()
        history_items = [
            {
                "agent_id": h.agent_id,
                "user_id": h.user_id,
                "tool_name": h.tool_name,
                "operation": h.operation,
                "decision": h.decision,
                "created_at": h.created_at,
            }
            for h in reversed(history_rows)
        ]

        # 3. Execute Threat Detection Coordinator
        threat_result = threat_coordinator.analyze_action(
            request=request,
            provenance=getattr(request, "provenance_context", None),
            history=history_items,
        )

        # 4. Evaluate through the Core Decision Engine with threat signals
        decision = security_engine.evaluate_action(
            authenticated_user_id=user_id,
            authenticated_agent_id=agent.id,
            agent_status=agent.status,
            request=request,
            db_policies=db_policies,
            threat_result=threat_result,
        )

        # 5. Persist Threat Findings (if any)
        for tf in threat_result.findings:
            finding_model = ThreatFindingModel(
                id=str(tf.finding_id),
                request_id=str(request.request_id),
                user_id=user_id,
                agent_id=agent.id,
                detector_id=tf.detector_id,
                threat_type=tf.threat_type.value if hasattr(tf.threat_type, "value") else str(tf.threat_type),
                title=tf.title,
                description=tf.description,
                severity=tf.severity.value if hasattr(tf.severity, "value") else str(tf.severity),
                confidence=tf.confidence.value if hasattr(tf.confidence, "value") else str(tf.confidence),
                risk_contribution=tf.risk_contribution,
                evidence_json=json.dumps(tf.evidence) if tf.evidence else None,
                affected_resource=tf.affected_resource,
                recommended_action=tf.recommended_action,
                status=tf.status.value if hasattr(tf.status, "value") else str(tf.status),
                detector_version=tf.detector_version,
            )
            self.session.add(finding_model)

        # 6. If decision is ASK_HUMAN, create pending ApprovalRequest record
        if decision.decision == Decision.ASK_HUMAN and decision.approval_id:
            req_hash = compute_canonical_request_hash(request)
            now_utc = datetime.now(timezone.utc)
            approval = ApprovalRequest(
                id=str(decision.approval_id),
                user_id=user_id,
                agent_id=agent.id,
                request_id=str(request.request_id),
                tool_name=request.tool_name,
                operation=request.operation or "execute",
                risk_level=decision.risk_level.value,
                description=f"Action requires approval. Hash: {req_hash[:16]}... Reason: {decision.reasons[0] if decision.reasons else 'Risk threshold exceeded.'}",
                status="pending",
                created_at=now_utc,
                expires_at=now_utc + timedelta(seconds=decision.approval_timeout_seconds or 300),
            )
            self.session.add(approval)

        # 4. Persist SecurityDecisionModel to DB
        dec_model = SecurityDecisionModel(
            id=str(decision.decision_id),
            request_id=str(decision.request_id),
            user_id=user_id,
            agent_id=agent.id,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level.value,
            reasons_json=json.dumps(decision.reasons),
            matched_policy_ids_json=json.dumps(decision.matched_policy_ids),
            policy_version=decision.policy_version,
            approval_required=decision.approval_required,
            approval_id=str(decision.approval_id) if decision.approval_id else None,
            evaluation_duration_ms=decision.evaluation_duration_ms,
        )
        self.session.add(dec_model)

        # 5. Persist corresponding ActivityEvent record
        act_event = ActivityEvent(
            request_id=str(request.request_id),
            user_id=user_id,
            agent_id=agent.id,
            tool_name=request.tool_name,
            operation=request.operation or "invoke",
            decision=decision.decision.value,
            risk_level=decision.risk_level.value,
            execution_status="approved" if decision.decision == Decision.ALLOW else "denied",
            arguments_summary=str(list(request.arguments.keys())) if request.arguments else None,
        )
        self.session.add(act_event)

        # 6. Append to tamper-evident cryptographically chained audit log
        try:
            audit_svc = TamperEvidentAuditService(self.session)
            await audit_svc.record_audit_entry(
                tenant_id=user_id,
                actor_id=agent.id,
                action=f"{request.tool_name}:{request.operation or 'invoke'}",
                target=request.resource or request.tool_name,
                result=decision.decision.value,
                description=f"Evaluated {request.tool_name} with decision {decision.decision.value}. Risk: {decision.risk_level.value}",
                agent_id=agent.id,
                event_type="security.action_evaluated",
            )
        except Exception as audit_err:
            logger.warning("Failed to record tamper-evident audit entry: %s", audit_err)

        await self.session.commit()

        # 8. Broadcast Real-Time WebSocket Events
        event_payload = {
            "decision_id": str(decision.decision_id),
            "request_id": str(decision.request_id),
            "agent_id": agent.id,
            "tool_name": request.tool_name,
            "operation": request.operation,
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "risk_level": decision.risk_level.value,
            "reasons": decision.reasons,
        }
        await broadcaster.broadcast_event(user_id, "security.decision.created", event_payload)

        if decision.decision == Decision.BLOCK:
            await broadcaster.broadcast_event(user_id, "security.action.blocked", event_payload)
        elif decision.decision == Decision.ASK_HUMAN:
            await broadcaster.broadcast_event(user_id, "security.approval.required", event_payload)

        # Broadcast Threat Events
        for tf in threat_result.findings:
            await broadcaster.broadcast_event(
                user_id,
                "threat.finding.created",
                {
                    "finding_id": str(tf.finding_id),
                    "request_id": str(request.request_id),
                    "agent_id": agent.id,
                    "threat_type": tf.threat_type.value if hasattr(tf.threat_type, "value") else str(tf.threat_type),
                    "title": tf.title,
                    "severity": tf.severity.value if hasattr(tf.severity, "value") else str(tf.severity),
                    "confidence": tf.confidence.value if hasattr(tf.confidence, "value") else str(tf.confidence),
                },
            )

        for corr in threat_result.correlations:
            await broadcaster.broadcast_event(
                user_id,
                "threat.correlation.created",
                {
                    "correlation_id": str(corr.correlation_id),
                    "agent_id": agent.id,
                    "threat_score": corr.threat_score,
                    "overall_severity": corr.overall_severity.value if hasattr(corr.overall_severity, "value") else str(corr.overall_severity),
                    "title": corr.title,
                },
            )

        if threat_result.incomplete_analysis:
            await broadcaster.broadcast_event(
                user_id,
                "threat.analysis.incomplete",
                {
                    "request_id": str(request.request_id),
                    "agent_id": agent.id,
                    "errors": threat_result.analysis_errors,
                },
            )

        return decision

    async def list_decisions(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        agent_id: str | None = None,
        decision: str | None = None,
        risk_level: str | None = None,
    ) -> PaginatedResponse[dict]:
        """List historical security decisions for user with pagination and filters."""
        query = select(SecurityDecisionModel).where(SecurityDecisionModel.user_id == user_id)
        count_q = select(func.count(SecurityDecisionModel.id)).where(SecurityDecisionModel.user_id == user_id)

        if agent_id:
            query = query.where(SecurityDecisionModel.agent_id == agent_id)
            count_q = count_q.where(SecurityDecisionModel.agent_id == agent_id)
        if decision:
            query = query.where(SecurityDecisionModel.decision == decision.upper())
            count_q = count_q.where(SecurityDecisionModel.decision == decision.upper())
        if risk_level:
            query = query.where(SecurityDecisionModel.risk_level == risk_level.upper())
            count_q = count_q.where(SecurityDecisionModel.risk_level == risk_level.upper())

        total = (await self.session.execute(count_q)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(SecurityDecisionModel.created_at.desc()).offset(offset).limit(size)
        rows = (await self.session.execute(query)).scalars().all()

        items = []
        for r in rows:
            reasons = json.loads(r.reasons_json) if r.reasons_json else []
            matched = json.loads(r.matched_policy_ids_json) if r.matched_policy_ids_json else []
            items.append({
                "id": r.id,
                "request_id": r.request_id,
                "agent_id": r.agent_id,
                "decision": r.decision,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "reasons": reasons,
                "matched_policy_ids": matched,
                "policy_version": r.policy_version,
                "approval_required": r.approval_required,
                "approval_id": r.approval_id,
                "evaluation_duration_ms": r.evaluation_duration_ms,
                "created_at": r.created_at,
            })

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)

    async def get_decision_by_id(self, decision_id: str, user_id: str) -> dict | None:
        stmt = select(SecurityDecisionModel).where(
            SecurityDecisionModel.id == decision_id,
            SecurityDecisionModel.user_id == user_id,
        )
        r = (await self.session.execute(stmt)).scalar_one_or_none()
        if not r:
            return None
        return {
            "id": r.id,
            "request_id": r.request_id,
            "agent_id": r.agent_id,
            "decision": r.decision,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "reasons": json.loads(r.reasons_json) if r.reasons_json else [],
            "matched_policy_ids": json.loads(r.matched_policy_ids_json) if r.matched_policy_ids_json else [],
            "policy_version": r.policy_version,
            "approval_required": r.approval_required,
            "approval_id": r.approval_id,
            "evaluation_duration_ms": r.evaluation_duration_ms,
            "created_at": r.created_at,
        }
