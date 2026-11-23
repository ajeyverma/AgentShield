"""
AgentShield AI — MCP Authorization Service (Phase 8).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import SecurityDecision
from agentshield.contracts.enums import Decision, RiskLevel
from agentshield.contracts.execution import ExecutionAuthorizationGrant, ExecutionRequest
from agentshield.database.models.agent import Agent
from agentshield.database.models.approval import ApprovalRequest
from agentshield.database.models.policy import Policy
from agentshield.database.models.security_decision import SecurityDecisionModel
from agentshield.database.models.threat_finding import ThreatFindingModel
from agentshield.database.models.execution import ToolExecutionModel
from agentshield.execution.authorization import authorization_manager
from agentshield.execution.enums import ExecutionStatus
from agentshield.mcp_gateway.exceptions import MCPApprovalRequiredError, MCPBlockedError, MCPSecurityError
from agentshield.mcp_gateway.security.policy_adapter import MCPPolicyAdapter
from agentshield.security.engine import security_engine
from agentshield.threat_detection.engine import threat_coordinator

logger = logging.getLogger("agentshield.mcp_gateway.authorization")


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class MCPAuthorizationService:
    """
    Evaluates MCP protocol operations against AgentShield Threat Detection (Phase 5)
    and Core Security Decision Engine (Phase 4).
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def evaluate_operation(
        self,
        user_id: str,
        agent_id: str,
        method: str,
        params: dict[str, Any],
        approval_id: str | None = None,
        request_id: str | None = None,
    ) -> tuple[SecurityDecision, ExecutionAuthorizationGrant]:
        """
        Evaluate and authorize an MCP operation.
        Returns (SecurityDecision, ExecutionAuthorizationGrant).
        Raises MCPBlockedError if blocked, or MCPApprovalRequiredError if human approval is pending.
        """
        action_req = MCPPolicyAdapter.create_action_request(
            user_id=user_id,
            agent_id=agent_id,
            method=method,
            params=params,
            request_id=request_id,
        )
        arguments = action_req.arguments
        arg_hash = MCPPolicyAdapter.get_argument_hash(arguments)

        # 1. If approval_id is supplied, verify and consume the grant
        if approval_id:
            return await self._verify_and_consume_approval(
                user_id=user_id,
                agent_id=agent_id,
                action_req=action_req,
                approval_id=approval_id,
                arg_hash=arg_hash,
            )

        # 2. Run Phase 5 Threat Detection
        threat_analysis = threat_coordinator.analyze_action(request=action_req)
        threat_findings = threat_analysis.findings

        # Persist findings to database
        for tf in threat_findings:
            db_finding = ThreatFindingModel(
                id=str(tf.finding_id),
                user_id=user_id,
                agent_id=str(action_req.agent_id),
                request_id=str(action_req.request_id),
                threat_type=tf.threat_type.value,
                severity=tf.severity.value,
                confidence=tf.confidence.value,
                title=tf.title,
                description=tf.description,
                recommended_action=tf.recommended_action,
                detector_id=tf.detector_id,
                evidence_json=json.dumps(tf.evidence),
                risk_contribution=tf.risk_contribution,
                status="open",
            )
            self.session.add(db_finding)

        # 3. Load active tenant policies
        policy_stmt = select(Policy).where(
            Policy.user_id == user_id,
            Policy.is_enabled == True,  # noqa: E712
        )
        res = await self.session.execute(policy_stmt)
        active_policies = list(res.scalars().all())

        # 4. Evaluate via Phase 4 Security Engine
        decision = security_engine.evaluate_action(
            authenticated_user_id=user_id,
            authenticated_agent_id=agent_id,
            agent_status="active",
            request=action_req,
            db_policies=active_policies,
            threat_result=threat_analysis,
        )

        # Persist decision record
        db_decision = SecurityDecisionModel(
            id=str(decision.decision_id),
            user_id=user_id,
            agent_id=str(action_req.agent_id),
            request_id=str(action_req.request_id),
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level.value,
            reasons_json=json.dumps(decision.reasons),
            matched_policy_ids_json=json.dumps(decision.matched_policy_ids),
            policy_version=1,
            approval_required=decision.approval_required,
            approval_id=str(decision.approval_id) if decision.approval_id else None,
            evaluation_duration_ms=decision.evaluation_duration_ms,
        )
        self.session.add(db_decision)

        # 5. Handle Security Decision Outcomes
        if decision.decision == Decision.BLOCK:
            await self.session.commit()
            reasons = "; ".join(decision.reasons) if decision.reasons else "Operation blocked by security policy"
            raise MCPBlockedError(
                message=f"AgentShield MCP Gateway blocked operation: {reasons}",
                details={
                    "request_id": str(action_req.request_id),
                    "decision_id": str(decision.decision_id),
                    "risk_score": decision.risk_score,
                    "reasons": decision.reasons,
                },
            )

        if decision.decision == Decision.ASK_HUMAN:
            # Create ApprovalRequest
            appr_id = str(uuid.uuid4())
            expires_at = datetime.now(UTC) + timedelta(minutes=15)
            approval = ApprovalRequest(
                id=appr_id,
                user_id=user_id,
                agent_id=str(action_req.agent_id),
                request_id=str(action_req.request_id),
                tool_name=action_req.tool_name,
                operation=action_req.operation,
                risk_level=decision.risk_level.value,
                description=f"MCP operation '{action_req.tool_name}' requires authorization. Risk score: {decision.risk_score:.1f}",
                status="pending",
                expires_at=expires_at,
            )
            self.session.add(approval)

            # Record execution row
            exec_record = ToolExecutionModel(
                id=str(uuid.uuid4()),
                user_id=user_id,
                agent_id=str(action_req.agent_id),
                request_id=str(action_req.request_id),
                tool_name=action_req.tool_name,
                action_name=action_req.operation,
                decision=decision.decision.value,
                status=ExecutionStatus.PENDING_APPROVAL.value,
                canonical_argument_hash=arg_hash,
                arguments_json=json.dumps(arguments),
                approval_id=appr_id,
            )
            self.session.add(exec_record)
            await self.session.commit()

            raise MCPApprovalRequiredError(
                message=f"MCP operation '{action_req.tool_name}' paused: human approval required",
                approval_id=appr_id,
                details={
                    "request_id": str(action_req.request_id),
                    "approval_id": appr_id,
                    "tool_name": action_req.tool_name,
                    "risk_score": decision.risk_score,
                    "expires_at": expires_at.isoformat(),
                },
            )

        # Decision.ALLOW -> Issue single-use execution grant
        await self.session.commit()
        exec_req = ExecutionRequest(
            request_id=action_req.request_id,
            agent_id=action_req.agent_id,
            user_id=str(action_req.user_id) if action_req.user_id else None,
            tool_name=action_req.tool_name,
            action_name=action_req.operation,
            arguments=arguments,
            canonical_argument_hash=arg_hash,
        )
        grant = authorization_manager.issue_grant(
            request=exec_req,
            decision_id=str(decision.decision_id),
            ttl_seconds=120,
        )
        return decision, grant

    async def _verify_and_consume_approval(
        self,
        user_id: str,
        agent_id: str,
        action_req: ActionRequest,
        approval_id: str,
        arg_hash: str,
    ) -> tuple[SecurityDecision, ExecutionAuthorizationGrant]:
        """Verify an existing approval request and consume it."""
        stmt = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.user_id == user_id,
        )
        res = await self.session.execute(stmt)
        approval = res.scalar_one_or_none()

        if not approval:
            raise MCPBlockedError(f"Approval request '{approval_id}' was not found or does not belong to this tenant.")

        if approval.status == "pending":
            raise MCPApprovalRequiredError(
                message=f"Approval request '{approval_id}' is still pending human authorization.",
                approval_id=approval_id,
            )

        if approval.status != "approved":
            raise MCPBlockedError(f"Approval request '{approval_id}' is not in approved state (status: {approval.status}).")

        # Check expiration
        now = datetime.now(UTC)
        if approval.expires_at:
            exp = _ensure_utc(approval.expires_at)
            if exp and exp < now:
                approval.status = "expired"
                await self.session.commit()
                raise MCPBlockedError(f"Approval request '{approval_id}' has expired.")

        # Check argument integrity via execution record or match
        exec_stmt = select(ToolExecutionModel).where(
            ToolExecutionModel.approval_id == approval_id,
            ToolExecutionModel.user_id == user_id,
        )
        exec_res = await self.session.execute(exec_stmt)
        exec_rec = exec_res.scalar_one_or_none()

        if exec_rec:
            if exec_rec.canonical_argument_hash != arg_hash:
                raise MCPBlockedError("Approval argument tamper detected: canonical argument hash does not match original request.")
            if exec_rec.status == ExecutionStatus.COMPLETED.value:
                raise MCPBlockedError(f"Approval request '{approval_id}' has already been consumed (single-use grant violated).")

            # Mark executed / consumed
            exec_rec.status = ExecutionStatus.COMPLETED.value

        approval.status = "executed"
        await self.session.commit()

        # Generate synthetic approved decision and grant
        decision = SecurityDecision(
            decision_id=uuid.uuid4(),
            request_id=action_req.request_id,
            decision=Decision.ALLOW,
            risk_score=10.0,
            risk_level=RiskLevel.LOW,
            reasons=[f"Approved by authorized human operator (approval_id: {approval_id})"],
            approval_required=False,
            evaluation_duration_ms=1.0,
        )
        exec_req = ExecutionRequest(
            request_id=action_req.request_id,
            agent_id=action_req.agent_id,
            user_id=str(action_req.user_id) if action_req.user_id else None,
            tool_name=action_req.tool_name,
            action_name=action_req.operation,
            arguments=action_req.arguments,
            canonical_argument_hash=arg_hash,
        )
        grant = authorization_manager.issue_grant(
            request=exec_req,
            decision_id=str(decision.decision_id),
            ttl_seconds=120,
        )
        return decision, grant
