"""
AgentShield AI — Policy Simulation Service (Phase 10).

Executes synthetic security evaluations against current active policies
WITHOUT invoking real tool adapters or modifying protected resources.
"""

from __future__ import annotations

import uuid
from typing import Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, IntegrationType, ToolCategory
from agentshield.database.models.policy import Policy
from agentshield.security.engine import security_engine
from agentshield.security.evaluator import compute_canonical_request_hash
from agentshield.services.schemas import PolicySimulationRequest, PolicySimulationResponse
from agentshield.threat_detection.engine import threat_coordinator


def _is_valid_uuid(val: str | None) -> bool:
    if not val:
        return False
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, AttributeError):
        return False


class PolicySimulationService:
    """Service simulating security evaluation and policy outcomes safely."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def simulate(
        self,
        user_id: str,
        request: PolicySimulationRequest,
    ) -> PolicySimulationResponse:
        """Run safe synthetic evaluation without executing tools."""
        # 1. Fetch active user policies
        stmt = select(Policy).where(Policy.user_id == user_id, Policy.is_enabled == True)
        policies = list((await self.session.execute(stmt)).scalars().all())

        # 2. Derive tool category
        t_name = request.tool_name.lower()
        if "fs" in t_name or "file" in t_name or "disk" in t_name:
            category = ToolCategory.FILE_SYSTEM
        elif "cmd" in t_name or "bash" in t_name or "sh" in t_name or "term" in t_name:
            category = ToolCategory.TERMINAL
        elif "http" in t_name or "fetch" in t_name or "net" in t_name:
            category = ToolCategory.NETWORK
        else:
            category = ToolCategory.UNKNOWN

        # 3. Construct synthetic ActionRequest
        agent_uuid = uuid.UUID(request.agent_id) if _is_valid_uuid(request.agent_id) else uuid.uuid4()
        user_uuid = uuid.UUID(user_id) if _is_valid_uuid(user_id) else uuid.uuid4()

        try:
            integ = IntegrationType(request.integration_type)
        except Exception:
            integ = IntegrationType.SDK

        action_req = ActionRequest(
            request_id=uuid.uuid4(),
            user_id=user_uuid,
            agent_id=agent_uuid,
            tenant_id=user_uuid,
            integration_type=integ,
            tool_name=request.tool_name,
            operation=request.operation,
            arguments=request.arguments or {},
            resource=request.resource or "",
            tool_category=category,
        )

        # 4. Run threat analysis (passive/in-memory)
        threat_result = threat_coordinator.analyze_action(action_req)

        # 5. Run security evaluation (passive/in-memory)
        decision = security_engine.evaluate_action(
            authenticated_user_id=user_id,
            authenticated_agent_id=str(agent_uuid),
            agent_status="active",
            request=action_req,
            db_policies=policies,
            threat_result=threat_result,
        )

        # 6. Format threat findings
        findings_summary: list[dict[str, Any]] = []
        if threat_result and hasattr(threat_result, "findings"):
            for f in threat_result.findings:
                findings_summary.append({
                    "detector_id": f.detector_id,
                    "threat_type": f.threat_type.value if hasattr(f.threat_type, "value") else str(f.threat_type),
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                    "risk_contribution": f.risk_contribution,
                    "description": f.description,
                })

        first_match = decision.matched_policies[0] if decision.matched_policies else None

        return PolicySimulationResponse(
            simulated_decision=decision.decision.value,
            decision_source="policy_engine",
            matched_policy_id=str(first_match.policy_id) if first_match else None,
            matched_policy_name=first_match.policy_name if first_match else None,
            matched_priority=first_match.priority if first_match and hasattr(first_match, "priority") else None,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level.value,
            threat_findings=findings_summary,
            reasons=decision.reasons,
            executed_real_tool=False,
        )
