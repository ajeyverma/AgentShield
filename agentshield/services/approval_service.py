"""
AgentShield AI — Approval Service (Phase 10).

Authoritative service for human-in-the-loop approval workflows, enforcing
role-based permissions, risk evaluation, zero self-approval, one-time execution,
and immutable audit history.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.events import EventComponent, EventSeverity
from agentshield.core.exceptions import ApprovalNotFoundError, AuthorizationError, ValidationError
from agentshield.database.models.approval import ApprovalHistory, ApprovalRequest
from agentshield.execution.exceptions import ApprovalVerificationError
from agentshield.observability.event_publisher import event_publisher
from agentshield.realtime.event_broadcaster import broadcaster
from agentshield.security.rbac import (
    UserRole,
    assert_not_agent_self_approval,
    can_approve_risk,
)
from agentshield.security.sanitization import redact_secrets
from agentshield.services.schemas import (
    ApprovalCreate,
    ApprovalDetailResponse,
    ApprovalHistoryResponse,
    ApprovalResponse,
    ApprovalUpdate,
    PaginatedResponse,
)
from agentshield.services.tamper_evident_audit import TamperEvidentAuditService

logger = logging.getLogger("agentshield.services.approval")


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class ApprovalService:
    """Manages human approval requests, enforcement checks, and execution resolution."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_approvals(
        self,
        user_id: str,
        page: int = 1,
        size: int = 20,
        status: str | None = None,
        agent_id: str | None = None,
        tool_name: str | None = None,
        search: str | None = None,
    ) -> PaginatedResponse[ApprovalResponse]:
        """Query approval requests with optional filters and full-text search."""
        query = select(ApprovalRequest).where(ApprovalRequest.user_id == user_id)
        count_query = select(func.count(ApprovalRequest.id)).where(ApprovalRequest.user_id == user_id)

        if status:
            query = query.where(ApprovalRequest.status == status.lower())
            count_query = count_query.where(ApprovalRequest.status == status.lower())

        if agent_id:
            query = query.where(ApprovalRequest.agent_id == agent_id)
            count_query = count_query.where(ApprovalRequest.agent_id == agent_id)

        if tool_name:
            query = query.where(ApprovalRequest.tool_name == tool_name)
            count_query = count_query.where(ApprovalRequest.tool_name == tool_name)

        if search and search.strip():
            s = f"%{search.strip()}%"
            filter_expr = or_(
                ApprovalRequest.tool_name.ilike(s),
                ApprovalRequest.operation.ilike(s),
                ApprovalRequest.description.ilike(s),
            )
            query = query.where(filter_expr)
            count_query = count_query.where(filter_expr)

        total = (await self.session.execute(count_query)).scalar() or 0
        offset = (page - 1) * size
        query = query.order_by(ApprovalRequest.created_at.desc()).offset(offset).limit(size)
        items = (await self.session.execute(query)).scalars().all()

        pages = math.ceil(total / size) if size > 0 else 0
        return PaginatedResponse(
            items=[ApprovalResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            size=size,
            pages=pages,
        )

    async def get_by_id(self, approval_id: str, user_id: str) -> ApprovalResponse | None:
        """Fetch an approval request by ID."""
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        res = (await self.session.execute(stmt)).scalar_one_or_none()
        return ApprovalResponse.model_validate(res) if res else None

    async def get_detail(self, approval_id: str, user_id: str) -> ApprovalDetailResponse | None:
        """Fetch approval details with parsed threat findings and redacted arguments."""
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        appr = (await self.session.execute(stmt)).scalar_one_or_none()
        if not appr:
            return None

        # Parse and sanitize arguments
        raw_args = {}
        if appr.arguments_json:
            try:
                raw_args = json.loads(appr.arguments_json)
            except Exception:
                raw_args = {}
        sanitized_args = redact_secrets(raw_args)

        # Parse threat findings
        threats = []
        if appr.threat_findings_json:
            try:
                threats = json.loads(appr.threat_findings_json)
            except Exception:
                threats = []

        base_dict = {c.name: getattr(appr, c.name) for c in appr.__table__.columns}
        base_dict["sanitized_arguments"] = sanitized_args
        base_dict["threat_findings"] = threats
        return ApprovalDetailResponse(**base_dict)

    async def approve_request(
        self,
        approval_id: str,
        user_id: str,
        user_role: str | UserRole,
        comment: str | None = None,
        is_agent_caller: bool = False,
    ) -> ApprovalResponse:
        """Approve a pending request and resume execution through the gateway."""
        # 1. Zero agent self-approval
        assert_not_agent_self_approval(is_agent_caller=is_agent_caller)

        # 2. Retrieve approval record
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        approval = (await self.session.execute(stmt)).scalar_one_or_none()
        if not approval:
            raise ApprovalNotFoundError(f"Approval request '{approval_id}' not found.")

        # 3. Verify current status is pending
        if approval.status != "pending":
            raise ApprovalVerificationError(
                f"Cannot approve request with status '{approval.status}'. Must be 'pending'."
            )

        # 4. Expiration check
        now = datetime.now(UTC)
        if approval.expires_at and now > _to_utc(approval.expires_at):
            approval.status = "expired"
            history = ApprovalHistory(
                approval_id=approval.id,
                user_id=user_id,
                action="expire",
                previous_status="pending",
                new_status="expired",
                performed_by="system",
                performer_role="SYSTEM",
                comment="Approval expired before decision.",
            )
            self.session.add(history)
            await self.session.commit()
            await broadcaster.broadcast_event(
                user_id,
                "approval.expired",
                {"approval_id": approval.id, "reason": "Approval window expired."},
            )
            raise ApprovalVerificationError("Approval request has expired.")

        # 5. Authorize approver role based on risk level
        risk_score = approval.risk_score or (80.0 if approval.risk_level in ("HIGH", "CRITICAL") else 50.0)
        if not can_approve_risk(user_role, risk_score, approval.risk_level):
            raise AuthorizationError(
                f"User with role '{user_role}' is not authorized to approve high-risk actions (risk score {risk_score:.0f}). OWNER or SECURITY_ADMIN required."
            )

        # 6. Execute through gateway if bound to an execution
        if approval.execution_id:
            from agentshield.services.execution_service import ExecutionService

            exec_service = ExecutionService(self.session)
            # approve_and_execute validates integrity, checks emergency controls, and invokes adapter
            await exec_service.approve_and_execute(
                execution_id=approval.execution_id,
                user_id=user_id,
                notes=comment,
            )

        # 7. Update approval state
        prev_status = approval.status
        approval.status = "approved"
        approval.reviewed_by = user_id
        approval.reviewer_role = str(user_role)
        approval.reviewed_at = now
        approval.review_comment = comment

        # 8. Record immutable audit history
        history = ApprovalHistory(
            approval_id=approval.id,
            user_id=user_id,
            action="approve",
            previous_status=prev_status,
            new_status="approved",
            performed_by=user_id,
            performer_role=str(user_role),
            comment=comment,
        )
        self.session.add(history)
        await self.session.commit()
        await self.session.refresh(approval)

        # 9. Broadcast real-time notification
        await broadcaster.broadcast_event(
            user_id,
            "approval.granted",
            {
                "approval_id": approval.id,
                "execution_id": approval.execution_id,
                "reviewed_by": user_id,
                "reviewer_role": str(user_role),
                "comment": comment,
            },
        )

        # 10. Record tamper-evident audit & publish security event
        audit_svc = TamperEvidentAuditService(self.session)
        await audit_svc.record_audit_entry(
            tenant_id=user_id,
            actor_id=user_id,
            actor_role=str(user_role),
            action="approval.granted",
            target=f"approval:{approval.id}",
            target_type="approval",
            result="SUCCESS",
            details={
                "approval_id": approval.id,
                "execution_id": approval.execution_id,
                "tool_name": approval.tool_name,
                "operation": approval.operation,
                "comment": comment,
            },
        )
        await event_publisher.publish(
            session=self.session,
            event_type="approval.granted",
            severity=EventSeverity.INFO,
            component=EventComponent.APPROVAL,
            tenant_id=user_id,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.operation,
            decision="ALLOW",
            status="approved",
            details={"approval_id": approval.id, "reviewed_by": user_id, "reviewer_role": str(user_role)},
        )

        logger.info(
            "Approval '%s' GRANTED by user '%s' (%s) for tool '%s'",
            approval_id,
            user_id,
            user_role,
            approval.tool_name,
        )
        return ApprovalResponse.model_validate(approval)

    async def reject_request(
        self,
        approval_id: str,
        user_id: str,
        user_role: str | UserRole,
        rejection_reason: str,
        is_agent_caller: bool = False,
    ) -> ApprovalResponse:
        """Reject a pending approval request, halting execution."""
        assert_not_agent_self_approval(is_agent_caller=is_agent_caller)

        if not rejection_reason or not rejection_reason.strip():
            raise ValidationError("A rejection reason must be provided.")

        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        approval = (await self.session.execute(stmt)).scalar_one_or_none()
        if not approval:
            raise ApprovalNotFoundError(f"Approval request '{approval_id}' not found.")

        if approval.status != "pending":
            raise ApprovalVerificationError(
                f"Cannot reject request with status '{approval.status}'. Must be 'pending'."
            )

        # Halt execution if linked
        if approval.execution_id:
            from agentshield.database.models.execution import ToolExecutionModel
            from agentshield.execution.enums import ExecutionStatus

            stmt_exec = select(ToolExecutionModel).where(ToolExecutionModel.id == approval.execution_id)
            exec_model = (await self.session.execute(stmt_exec)).scalar_one_or_none()
            if exec_model:
                exec_model.status = ExecutionStatus.BLOCKED.value
                exec_model.error_code = "APPROVAL_REJECTED"
                exec_model.error_message = f"Rejected by approver: {rejection_reason}"
                exec_model.completed_at = datetime.now(UTC)

        prev_status = approval.status
        now = datetime.now(UTC)
        approval.status = "rejected"
        approval.reviewed_by = user_id
        approval.reviewer_role = str(user_role)
        approval.reviewed_at = now
        approval.rejection_reason = rejection_reason.strip()

        history = ApprovalHistory(
            approval_id=approval.id,
            user_id=user_id,
            action="reject",
            previous_status=prev_status,
            new_status="rejected",
            performed_by=user_id,
            performer_role=str(user_role),
            comment=rejection_reason.strip(),
        )
        self.session.add(history)
        await self.session.commit()
        await self.session.refresh(approval)

        await broadcaster.broadcast_event(
            user_id,
            "approval.rejected",
            {
                "approval_id": approval.id,
                "execution_id": approval.execution_id,
                "rejected_by": user_id,
                "reviewer_role": str(user_role),
                "reason": rejection_reason.strip(),
            },
        )

        audit_svc = TamperEvidentAuditService(self.session)
        await audit_svc.record_audit_entry(
            tenant_id=user_id,
            actor_id=user_id,
            actor_role=str(user_role),
            action="approval.rejected",
            target=f"approval:{approval.id}",
            target_type="approval",
            result="SUCCESS",
            details={
                "approval_id": approval.id,
                "execution_id": approval.execution_id,
                "tool_name": approval.tool_name,
                "operation": approval.operation,
                "reason": rejection_reason.strip(),
            },
        )
        await event_publisher.publish(
            session=self.session,
            event_type="approval.rejected",
            severity=EventSeverity.WARNING,
            component=EventComponent.APPROVAL,
            tenant_id=user_id,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.operation,
            decision="BLOCK",
            status="rejected",
            details={"approval_id": approval.id, "rejected_by": user_id, "reviewer_role": str(user_role), "reason": rejection_reason.strip()},
        )

        logger.info("Approval '%s' REJECTED by user '%s': %s", approval_id, user_id, rejection_reason)
        return ApprovalResponse.model_validate(approval)

    async def cancel_request(
        self,
        approval_id: str,
        user_id: str,
        user_role: str | UserRole,
        reason: str | None = None,
        is_agent_caller: bool = False,
    ) -> ApprovalResponse:
        """Cancel a pending approval request."""
        assert_not_agent_self_approval(is_agent_caller=is_agent_caller)

        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        approval = (await self.session.execute(stmt)).scalar_one_or_none()
        if not approval:
            raise ApprovalNotFoundError(f"Approval request '{approval_id}' not found.")

        if approval.status != "pending":
            raise ApprovalVerificationError(
                f"Cannot cancel request with status '{approval.status}'. Must be 'pending'."
            )

        if approval.execution_id:
            from agentshield.services.execution_service import ExecutionService

            exec_service = ExecutionService(self.session)
            try:
                await exec_service.cancel_execution(approval.execution_id, user_id)
            except Exception as e:
                logger.warning("Error cancelling execution %s: %s", approval.execution_id, e)

        prev_status = approval.status
        now = datetime.now(UTC)
        approval.status = "cancelled"
        approval.reviewed_by = user_id
        approval.reviewer_role = str(user_role)
        approval.reviewed_at = now
        approval.review_comment = reason or "Cancelled by user."

        history = ApprovalHistory(
            approval_id=approval.id,
            user_id=user_id,
            action="cancel",
            previous_status=prev_status,
            new_status="cancelled",
            performed_by=user_id,
            performer_role=str(user_role),
            comment=reason or "Cancelled by user.",
        )
        self.session.add(history)
        await self.session.commit()
        await self.session.refresh(approval)

        await broadcaster.broadcast_event(
            user_id,
            "approval.cancelled",
            {
                "approval_id": approval.id,
                "cancelled_by": user_id,
                "reason": reason or "Cancelled by user.",
            },
        )

        audit_svc = TamperEvidentAuditService(self.session)
        await audit_svc.record_audit_entry(
            tenant_id=user_id,
            actor_id=user_id,
            actor_role=str(user_role),
            action="approval.cancelled",
            target=f"approval:{approval.id}",
            target_type="approval",
            result="SUCCESS",
            details={
                "approval_id": approval.id,
                "execution_id": approval.execution_id,
                "reason": reason or "Cancelled by user.",
            },
        )
        await event_publisher.publish(
            session=self.session,
            event_type="approval.cancelled",
            severity=EventSeverity.INFO,
            component=EventComponent.APPROVAL,
            tenant_id=user_id,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.operation,
            status="cancelled",
            details={"approval_id": approval.id, "cancelled_by": user_id},
        )
        return ApprovalResponse.model_validate(approval)

    async def get_history(self, approval_id: str, user_id: str) -> list[ApprovalHistoryResponse]:
        """Fetch audit trail history for an approval request."""
        stmt = (
            select(ApprovalHistory)
            .where(
                ApprovalHistory.approval_id == approval_id,
                ApprovalHistory.user_id == user_id,
            )
            .order_by(ApprovalHistory.created_at.asc())
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return [ApprovalHistoryResponse.model_validate(r) for r in rows]

    async def update_status(self, approval_id: str, user_id: str, data: ApprovalUpdate) -> ApprovalResponse:
        """Legacy update status method for Phase 3 compatibility."""
        if data.status == "approved":
            return await self.approve_request(approval_id, user_id, UserRole.OWNER)
        else:
            return await self.reject_request(approval_id, user_id, UserRole.OWNER, rejection_reason="Rejected via legacy API")

    async def create_approval_request(self, user_id: str, data: ApprovalCreate) -> ApprovalResponse:
        """Create a standalone approval request."""
        approval = ApprovalRequest(
            user_id=user_id,
            agent_id=data.agent_id,
            request_id=data.request_id,
            tool_name=data.tool_name,
            operation=data.operation,
            risk_level=data.risk_level.upper(),
            description=data.description,
            status="pending",
            expires_at=data.expires_at,
        )
        self.session.add(approval)
        await self.session.flush()
        await self.session.refresh(approval)
        await self.session.commit()
        return ApprovalResponse.model_validate(approval)
