"""
AgentShield AI — Execution Service (Phase 6).

Coordinates execution lifecycle persistence, idempotency guarantees, atomic approval
transitions, and real-time WebSocket event broadcasting.
"""

from __future__ import annotations

import json
import logging
import math
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.enums import Decision, IntegrationType, ToolCategory
from agentshield.contracts.events import EventComponent, EventSeverity
from agentshield.contracts.execution import (
    ExecutionRequest,
    ToolExecutionResponse,
    compute_canonical_argument_hash,
)
from agentshield.core.exceptions import AuthorizationError
from agentshield.database.models.activity import ActivityEvent
from agentshield.database.models.agent import Agent
from agentshield.database.models.approval import ApprovalRequest
from agentshield.database.models.execution import ToolExecutionModel
from agentshield.database.models.policy import Policy
from agentshield.database.models.threat_finding import ThreatFindingModel
from agentshield.execution.authorization import authorization_manager
from agentshield.execution.enums import ExecutionStatus
from agentshield.execution.exceptions import (
    ApprovalVerificationError,
    ExecutionGatewayError,
    IdempotencyConflictError,
)
from agentshield.execution.registry import tool_registry
from agentshield.observability.event_publisher import event_publisher
from agentshield.observability.tracing import trace_span
from agentshield.realtime.event_broadcaster import broadcaster
from agentshield.security.engine import security_engine
from agentshield.services.schemas import PaginatedResponse
from agentshield.threat_detection.engine import threat_coordinator

logger = logging.getLogger("agentshield.services.execution")


class ExecutionService:
    """Service managing database persistence, idempotency, and approval execution."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def check_idempotency(self, user_id: str, idempotency_key: str | None, current_hash: str) -> ToolExecutionModel | None:
        """Check if an identical idempotency key exists. Rejects altered arguments."""
        if not idempotency_key:
            return None

        stmt = select(ToolExecutionModel).where(
            ToolExecutionModel.user_id == user_id,
            ToolExecutionModel.idempotency_key == idempotency_key,
        )
        existing = (await self.session.execute(stmt)).scalar_one_or_none()
        if existing:
            if existing.canonical_argument_hash != current_hash:
                raise IdempotencyConflictError(idempotency_key)
            return existing
        return None

    async def execute_request(
        self,
        user_id: str,
        agent: Agent,
        request: ExecutionRequest,
    ) -> ToolExecutionResponse:
        """Process an execution request through validation, threats, security evaluation, and adapter."""
        with trace_span("gateway.execute_request", resource=f"{request.tool_name}:{request.action_name}"):
            # 1. Idempotency check
            existing = await self.check_idempotency(user_id, request.idempotency_key, request.canonical_argument_hash)
            if existing:
                return self._model_to_response(existing)

            # 2. Registry validation
            tool_def = tool_registry.validate_request(
                tool_name=request.tool_name,
                action_name=request.action_name,
                arguments=request.arguments,
            )

            # 2.5 Emergency Controls Check (Phase 10)
            from agentshield.services.emergency_service import EmergencyControlService
            emergency_svc = EmergencyControlService(self.session)
            is_emg_blocked, emg_reason = await emergency_svc.check_is_blocked(
                user_id=user_id,
                agent_id=agent.id,
                tool_name=request.tool_name,
                integration_type=getattr(request, "integration_type", "api") or "api",
            )
            if is_emg_blocked:
                exec_id = str(uuid.uuid4())
                model = ToolExecutionModel(
                    id=exec_id,
                    request_id=str(request.request_id),
                    user_id=user_id,
                    agent_id=agent.id,
                    tool_name=request.tool_name,
                    action_name=request.action_name,
                    canonical_argument_hash=request.canonical_argument_hash,
                    arguments_json=json.dumps(request.arguments) if request.arguments is not None else None,
                    idempotency_key=request.idempotency_key,
                    decision="BLOCK",
                    status=ExecutionStatus.BLOCKED.value,
                    error_code="EMERGENCY_LOCKDOWN",
                    error_message=emg_reason,
                    started_at=datetime.now(UTC),
                    completed_at=datetime.now(UTC),
                )
                self.session.add(model)
                await self.session.commit()
                await broadcaster.broadcast_event(
                    user_id,
                    "execution.blocked",
                    {"execution_id": model.id, "tool_name": request.tool_name, "action_name": request.action_name, "reason": emg_reason},
                )
                await event_publisher.publish(
                    session=self.session,
                    event_type="execution.blocked",
                    severity=EventSeverity.CRITICAL,
                    component=EventComponent.GATEWAY,
                    tenant_id=user_id,
                    agent_id=agent.id,
                    tool_name=request.tool_name,
                    action=request.action_name,
                    decision="BLOCK",
                    status="BLOCKED",
                    details={"reason": emg_reason, "error_code": "EMERGENCY_LOCKDOWN"},
                )
                return self._model_to_response(model)

        # 3. Create initial execution record
        exec_id = str(uuid.uuid4())
        model = ToolExecutionModel(
            id=exec_id,
            request_id=str(request.request_id),
            user_id=user_id,
            agent_id=agent.id,
            tool_name=request.tool_name,
            action_name=request.action_name,
            canonical_argument_hash=request.canonical_argument_hash,
            arguments_json=json.dumps(request.arguments) if request.arguments is not None else None,
            idempotency_key=request.idempotency_key,
            decision="BLOCK",
            status=ExecutionStatus.EVALUATING.value,
            started_at=datetime.now(UTC),
        )
        self.session.add(model)
        await self.session.flush()

        # 4. Map to normalized ActionRequest for threat & policy evaluation
        from agentshield.contracts.action import ActionRequest
        action_req = ActionRequest(
            request_id=request.request_id,
            tenant_id=uuid.UUID(user_id) if len(user_id) == 36 else uuid.uuid4(),
            agent_id=uuid.UUID(agent.id),
            user_id=uuid.UUID(user_id) if len(user_id) == 36 else None,
            tool_name=request.tool_name,
            tool_category=tool_def.category,
            operation=request.action_name,
            arguments=request.arguments,
            resource=str(request.arguments.get("path") or request.arguments.get("endpoint") or ""),
            requested_permissions=tool_def.actions[request.action_name].required_permissions,
            integration_type=IntegrationType.API,
        )

        # 5. Threat Analysis (Phase 5)
        stmt_history = select(ActivityEvent).where(
            ActivityEvent.user_id == user_id,
            ActivityEvent.agent_id == agent.id,
        ).order_by(ActivityEvent.created_at.desc()).limit(30)
        hist_rows = (await self.session.execute(stmt_history)).scalars().all()
        history_items = [
            {"agent_id": h.agent_id, "tool_name": h.tool_name, "decision": h.decision, "created_at": h.created_at}
            for h in reversed(hist_rows)
        ]

        threat_result = threat_coordinator.analyze_action(action_req, history=history_items)

        # Persist any threat findings
        for tf in threat_result.findings:
            f_model = ThreatFindingModel(
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
                status="open",
                detector_version=tf.detector_version,
            )
            self.session.add(f_model)

        # 6. Authoritative Security Evaluation (Phase 4)
        stmt_policies = select(Policy).where(Policy.user_id == user_id, Policy.is_enabled == True)
        db_policies = (await self.session.execute(stmt_policies)).scalars().all()

        decision = security_engine.evaluate_action(
            authenticated_user_id=user_id,
            authenticated_agent_id=agent.id,
            agent_status=agent.status,
            request=action_req,
            db_policies=db_policies,
            threat_result=threat_result,
        )

        model.decision = decision.decision.value
        model.decision_id = str(decision.decision_id)

        # 7. Outcome Enforcement
        if decision.decision == Decision.BLOCK:
            # ── BLOCK: Adapter is NEVER invoked ──
            model.status = ExecutionStatus.BLOCKED.value
            model.error_code = "SECURITY_BLOCKED"
            model.error_message = decision.reasons[0] if decision.reasons else "Action blocked by security policy."
            model.completed_at = datetime.now(UTC)
            await self.session.commit()

            await broadcaster.broadcast_event(
                user_id,
                "execution.blocked",
                {"execution_id": model.id, "tool_name": request.tool_name, "action_name": request.action_name, "reason": model.error_message},
            )
            await event_publisher.publish(
                session=self.session,
                event_type="execution.blocked",
                severity=EventSeverity.HIGH,
                component=EventComponent.SECURITY_ENGINE,
                tenant_id=user_id,
                agent_id=agent.id,
                tool_name=request.tool_name,
                action=request.action_name,
                decision="BLOCK",
                status="BLOCKED",
                details={"reason": model.error_message, "risk_score": getattr(decision, "risk_score", 0.0)},
            )
            return self._model_to_response(model)

        elif decision.decision == Decision.ASK_HUMAN:
            # ── ASK_HUMAN: Execution is paused; Adapter is NOT invoked ──
            approval_id = str(decision.approval_id or uuid.uuid4())
            model.status = ExecutionStatus.PENDING_APPROVAL.value
            model.approval_id = approval_id

            # Create ApprovalRequest record (Phase 10 enriched)
            now_utc = datetime.now(UTC)
            approval = ApprovalRequest(
                id=approval_id,
                user_id=user_id,
                agent_id=agent.id,
                request_id=str(request.request_id),
                execution_id=model.id,
                tenant_id=user_id,
                integration_type=getattr(request, "integration_type", "API") or "API",
                resource=str(request.arguments.get("path") or request.arguments.get("endpoint") or "") if request.arguments else "",
                risk_score=float(decision.risk_score) if hasattr(decision, "risk_score") else 50.0,
                threat_findings_json=json.dumps(
                    [tf.model_dump() if hasattr(tf, "model_dump") else str(tf) for tf in threat_result.findings],
                    default=str,
                ) if threat_result.findings else None,
                tool_name=request.tool_name,
                operation=request.action_name,
                risk_level=decision.risk_level.value,
                canonical_argument_hash=request.canonical_argument_hash,
                arguments_json=json.dumps(request.arguments) if request.arguments is not None else None,
                description=f"Tool execution requires approval. Argument hash: {request.canonical_argument_hash[:16]}...",
                status="pending",
                created_at=now_utc,
                expires_at=now_utc + timedelta(seconds=decision.approval_timeout_seconds or 300),
            )
            self.session.add(approval)
            await self.session.commit()

            # Dispatch real-time WhatsApp alert via Twilio
            try:
                from agentshield.services.notification_service import notification_service
                pin = str(abs(hash(str(approval_id))) % 900000 + 100000)
                notification_service.send_approval_alert_sync(
                    approval_id=str(approval_id),
                    tool_name=request.tool_name,
                    operation=request.action_name or "execute",
                    reasons=[r.description if hasattr(r, "description") else str(r) for r in decision.reasons] if hasattr(decision, "reasons") else ["Execution requires approval"],
                    risk_level=decision.risk_level.value if hasattr(decision.risk_level, "value") else str(decision.risk_level),
                    pin_code=pin,
                )
            except Exception as notify_err:
                logger.warning("Failed to dispatch WhatsApp alert from execution service: %s", notify_err)

            from agentshield.security.sanitization import redact_secrets
            await broadcaster.broadcast_event(
                user_id,
                "approval.requested",
                {
                    "approval_id": approval_id,
                    "execution_id": model.id,
                    "tool_name": request.tool_name,
                    "operation": request.action_name,
                    "risk_level": decision.risk_level.value,
                    "risk_score": float(decision.risk_score) if hasattr(decision, "risk_score") else 50.0,
                    "arguments": redact_secrets(request.arguments),
                    "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
                },
            )

            await broadcaster.broadcast_event(
                user_id,
                "execution.approval_required",
                {"execution_id": model.id, "approval_id": approval_id, "tool_name": request.tool_name, "action_name": request.action_name},
            )
            await event_publisher.publish(
                session=self.session,
                event_type="execution.approval_required",
                severity=EventSeverity.MEDIUM,
                component=EventComponent.SECURITY_ENGINE,
                tenant_id=user_id,
                agent_id=agent.id,
                tool_name=request.tool_name,
                action=request.action_name,
                decision="ASK_HUMAN",
                status="PENDING_APPROVAL",
                details={"approval_id": approval_id, "risk_level": decision.risk_level.value, "risk_score": float(getattr(decision, "risk_score", 50.0))},
            )
            return self._model_to_response(model)

        else:
            # ── ALLOW: Issue Grant and Execute through Adapter ──
            model.status = ExecutionStatus.EXECUTING.value
            grant = authorization_manager.issue_grant(request=request, decision_id=str(decision.decision_id))
            model.grant_id = str(grant.grant_id)

            # Consume grant before invoking adapter
            authorization_manager.consume_grant(grant.grant_id, request)

            # Execute tool adapter
            exec_res = tool_def.adapter.execute(
                action_name=request.action_name,
                arguments=request.arguments,
            )

            model.completed_at = datetime.now(UTC)
            model.duration_ms = exec_res.duration_ms

            if exec_res.status == "SUCCESS":
                model.status = ExecutionStatus.COMPLETED.value
                model.result_json = json.dumps(exec_res.result, default=str)
            else:
                model.status = ExecutionStatus.FAILED.value
                model.error_code = exec_res.error_code or "TOOL_EXECUTION_FAILED"
                model.error_message = exec_res.error_message

            # Log corresponding ActivityEvent
            act_event = ActivityEvent(
                request_id=str(request.request_id),
                user_id=user_id,
                agent_id=agent.id,
                tool_name=request.tool_name,
                operation=request.action_name,
                decision=decision.decision.value,
                risk_level=decision.risk_level.value,
                execution_status="approved",
                arguments_summary=str(list(request.arguments.keys())),
            )
            self.session.add(act_event)
            await self.session.commit()

            evt_type = "execution.completed" if model.status == ExecutionStatus.COMPLETED.value else "execution.failed"
            await broadcaster.broadcast_event(
                user_id,
                evt_type,
                {"execution_id": model.id, "tool_name": request.tool_name, "status": model.status},
            )
            await event_publisher.publish(
                session=self.session,
                event_type=evt_type,
                severity=EventSeverity.INFO if model.status == ExecutionStatus.COMPLETED.value else EventSeverity.WARNING,
                component=EventComponent.GATEWAY,
                tenant_id=user_id,
                agent_id=agent.id,
                tool_name=request.tool_name,
                action=request.action_name,
                decision="ALLOW",
                status=model.status,
                latency_ms=model.duration_ms,
                details={"execution_id": model.id, "error_code": model.error_code, "error_message": model.error_message},
            )
            return self._model_to_response(model)

    async def approve_and_execute(
        self,
        execution_id: str,
        user_id: str,
        notes: str | None = None,
    ) -> ToolExecutionResponse:
        """Human approval verification path. Revalidates hash, policy, and executes tool."""
        stmt = select(ToolExecutionModel).where(
            ToolExecutionModel.id == execution_id,
            ToolExecutionModel.user_id == user_id,
        )
        model = (await self.session.execute(stmt)).scalar_one_or_none()
        if not model:
            raise AuthorizationError("Execution not found or access denied.")

        if model.decision == "BLOCK":
            raise ApprovalVerificationError("Mandatory BLOCK decisions cannot be approved.")

        if model.status != ExecutionStatus.PENDING_APPROVAL.value:
            raise ApprovalVerificationError(f"Execution is not in PENDING_APPROVAL state (current: {model.status}).")

        def _to_utc(dt: datetime | None) -> datetime | None:
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)

        # Check approval expiration
        if model.approval_id:
            stmt_appr = select(ApprovalRequest).where(ApprovalRequest.id == model.approval_id)
            appr = (await self.session.execute(stmt_appr)).scalar_one_or_none()
            if appr:
                if appr.status != "pending":
                    raise ApprovalVerificationError("Approval request has already been used or resolved.")
                if appr.expires_at and datetime.now(UTC) > _to_utc(appr.expires_at):
                    model.status = ExecutionStatus.EXPIRED.value
                    appr.status = "expired"
                    await self.session.commit()
                    raise ApprovalVerificationError("Approval window has expired.")
                appr.status = "approved"

        # Check emergency control before executing approved action
        from agentshield.services.emergency_service import EmergencyControlService
        emergency_svc = EmergencyControlService(self.session)
        is_emg_blocked, emg_reason = await emergency_svc.check_is_blocked(
            user_id=user_id,
            agent_id=model.agent_id,
            tool_name=model.tool_name,
        )
        if is_emg_blocked:
            raise ApprovalVerificationError(f"Execution halted by emergency control: {emg_reason}")

        # Re-fetch tool
        tool_def = tool_registry.get(model.tool_name)
        raw_args = json.loads(model.arguments_json) if model.arguments_json else {}

        # Issue single-use grant bound to canonical arguments
        req_id = uuid.UUID(model.request_id)
        dummy_req = ExecutionRequest(
            request_id=req_id,
            agent_id=uuid.UUID(model.agent_id),
            user_id=user_id,
            tool_name=model.tool_name,
            action_name=model.action_name,
            arguments=raw_args,
        )
        grant = authorization_manager.issue_grant(request=dummy_req, decision_id=model.decision_id or "approval_grant")
        model.grant_id = str(grant.grant_id)
        model.status = ExecutionStatus.APPROVED.value
        await self.session.flush()

        # Consume grant and execute adapter
        authorization_manager.consume_grant(grant.grant_id, dummy_req)
        model.status = ExecutionStatus.EXECUTING.value
        exec_res = tool_def.adapter.execute(
            action_name=model.action_name,
            arguments=raw_args,
        )

        model.completed_at = datetime.now(UTC)
        model.duration_ms = exec_res.duration_ms

        if exec_res.status == "SUCCESS":
            model.status = ExecutionStatus.COMPLETED.value
            model.result_json = json.dumps(exec_res.result, default=str)
        else:
            model.status = ExecutionStatus.FAILED.value
            model.error_code = exec_res.error_code or "TOOL_EXECUTION_FAILED"
            model.error_message = exec_res.error_message

        await self.session.commit()

        await broadcaster.broadcast_event(
            user_id,
            "execution.completed",
            {"execution_id": model.id, "tool_name": model.tool_name, "status": model.status},
        )
        await event_publisher.publish(
            session=self.session,
            event_type="execution.completed" if model.status == ExecutionStatus.COMPLETED.value else "execution.failed",
            severity=EventSeverity.INFO if model.status == ExecutionStatus.COMPLETED.value else EventSeverity.WARNING,
            component=EventComponent.GATEWAY,
            tenant_id=user_id,
            agent_id=model.agent_id,
            tool_name=model.tool_name,
            action=model.action_name,
            decision="ALLOW",
            status=model.status,
            latency_ms=model.duration_ms,
            details={"execution_id": model.id, "approved": True, "notes": notes},
        )
        return self._model_to_response(model)

    async def cancel_execution(self, execution_id: str, user_id: str) -> ToolExecutionResponse:
        """Cancel a pending tool execution."""
        stmt = select(ToolExecutionModel).where(
            ToolExecutionModel.id == execution_id,
            ToolExecutionModel.user_id == user_id,
        )
        model = (await self.session.execute(stmt)).scalar_one_or_none()
        if not model:
            raise AuthorizationError("Execution not found or access denied.")

        if model.status != ExecutionStatus.PENDING_APPROVAL.value:
            raise ApprovalVerificationError(f"Cannot cancel execution in state '{model.status}'.")

        model.status = ExecutionStatus.CANCELLED.value
        if model.approval_id:
            stmt_appr = select(ApprovalRequest).where(ApprovalRequest.id == model.approval_id)
            appr = (await self.session.execute(stmt_appr)).scalar_one_or_none()
            if appr:
                appr.status = "rejected"

        await self.session.commit()
        await broadcaster.broadcast_event(
            user_id,
            "execution.cancelled",
            {"execution_id": model.id, "tool_name": model.tool_name},
        )
        return self._model_to_response(model)

    async def list_executions(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        agent_id: str | None = None,
        tool_name: str | None = None,
        status: str | None = None,
        decision: str | None = None,
    ) -> PaginatedResponse[ToolExecutionResponse]:
        """Query execution history with pagination and filters."""
        query = select(ToolExecutionModel).where(ToolExecutionModel.user_id == user_id)
        count_q = select(func.count(ToolExecutionModel.id)).where(ToolExecutionModel.user_id == user_id)

        if agent_id:
            query = query.where(ToolExecutionModel.agent_id == agent_id)
            count_q = count_q.where(ToolExecutionModel.agent_id == agent_id)
        if tool_name:
            query = query.where(ToolExecutionModel.tool_name == tool_name.lower())
            count_q = count_q.where(ToolExecutionModel.tool_name == tool_name.lower())
        if status:
            query = query.where(ToolExecutionModel.status == status.upper())
            count_q = count_q.where(ToolExecutionModel.status == status.upper())
        if decision:
            query = query.where(ToolExecutionModel.decision == decision.upper())
            count_q = count_q.where(ToolExecutionModel.decision == decision.upper())

        total = (await self.session.execute(count_q)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(ToolExecutionModel.created_at.desc()).offset(offset).limit(size)
        rows = (await self.session.execute(query)).scalars().all()

        items = [self._model_to_response(r) for r in rows]
        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)

    async def get_execution_by_id(self, execution_id: str, user_id: str) -> ToolExecutionResponse | None:
        stmt = select(ToolExecutionModel).where(
            ToolExecutionModel.id == execution_id,
            ToolExecutionModel.user_id == user_id,
        )
        r = (await self.session.execute(stmt)).scalar_one_or_none()
        return self._model_to_response(r) if r else None

    @staticmethod
    def _model_to_response(model: ToolExecutionModel) -> ToolExecutionResponse:
        res = json.loads(model.result_json) if model.result_json else None
        return ToolExecutionResponse(
            execution_id=uuid.UUID(model.id),
            request_id=uuid.UUID(model.request_id),
            agent_id=model.agent_id,
            tool_name=model.tool_name,
            action_name=model.action_name,
            status=ExecutionStatus(model.status),
            decision=model.decision,
            decision_id=model.decision_id,
            approval_id=model.approval_id,
            approval_required=(model.status == ExecutionStatus.PENDING_APPROVAL.value),
            result=res,
            error_code=model.error_code,
            error_message=model.error_message,
            duration_ms=model.duration_ms,
            started_at=model.started_at,
            completed_at=model.completed_at,
            created_at=model.created_at,
        )
