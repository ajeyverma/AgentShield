"""
AgentShield AI — Core Security Decision Engine & Evaluator (Phase 4).

The central decision authority for runtime agent action authorization.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Sequence

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import PolicyMatch, SecurityDecision
from agentshield.contracts.enums import Decision, RiskLevel
from agentshield.contracts.threat import ThreatAnalysisResult, ThreatSeverity
from agentshield.database.models.policy import Policy
from agentshield.security.permissions import AgentPermissions, PermissionEvaluator
from agentshield.security.policy_engine import PolicyEngine
from agentshield.security.risk_scoring import RiskScoringEngine

logger = logging.getLogger("agentshield.security.engine")


class SecurityDecisionEngine:
    """Independent security evaluation and authorization decision engine."""

    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self.policy_engine = policy_engine or PolicyEngine()

    def evaluate_action(
        self,
        authenticated_user_id: str,
        authenticated_agent_id: str,
        agent_status: str,
        request: ActionRequest,
        permissions: AgentPermissions | None = None,
        db_policies: Sequence[Policy] = (),
        threat_result: ThreatAnalysisResult | None = None,
    ) -> SecurityDecision:
        """Evaluate an ActionRequest and return an authoritative SecurityDecision.

        Fail-Closed Guarantee:
            Any unexpected internal error results in an immediate, safe BLOCK decision.
        """
        start_time = time.perf_counter()
        reasons: list[str] = []
        matched_policies: list[PolicyMatch] = []

        try:
            # ── 1. Identity & Ownership Boundary Verification ──────────────────
            if request.user_id and str(request.user_id) != str(authenticated_user_id):
                return self._build_fail_decision(
                    request=request,
                    reason="User identity mismatch: request claim does not match authenticated user.",
                    start_time=start_time,
                )

            if request.agent_id and str(request.agent_id) != str(authenticated_agent_id):
                return self._build_fail_decision(
                    request=request,
                    reason="Agent identity mismatch: request claim does not match authenticated agent.",
                    start_time=start_time,
                )

            if agent_status.lower() != "active":
                return self._build_fail_decision(
                    request=request,
                    reason=f"Agent '{authenticated_agent_id}' is {agent_status.upper()}: not authorized to execute actions.",
                    start_time=start_time,
                )

            # ── 2. Permission Evaluation (Least Privilege & Deny by Default) ──
            effective_perms = permissions or AgentPermissions(
                agent_id=authenticated_agent_id,
                owner_user_id=authenticated_user_id,
            )

            perm_result = PermissionEvaluator.evaluate(
                permissions=effective_perms,
                request=request,
                authenticated_user_id=authenticated_user_id,
                authenticated_agent_id=authenticated_agent_id,
            )

            if not perm_result.granted:
                return self._build_fail_decision(
                    request=request,
                    reason=perm_result.reason,
                    start_time=start_time,
                )

            # ── 3. Policy & Domain Rule Evaluation ─────────────────────────────
            policy_result = self.policy_engine.evaluate(request, db_policies)
            reasons.extend(policy_result.reasons)
            matched_policies.extend(policy_result.matched_policies)

            # Mandatory BLOCK takes absolute precedence
            if policy_result.decision == Decision.BLOCK:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return SecurityDecision(
                    request_id=request.request_id,
                    decision=Decision.BLOCK,
                    risk_score=95.0,
                    risk_level=RiskLevel.CRITICAL,
                    reasons=reasons,
                    matched_policies=matched_policies,
                    policy_version=policy_result.effective_version,
                    approval_required=False,
                    evaluated_at=datetime.now(UTC),
                    evaluation_duration_ms=round(duration_ms, 2),
                )

            # ── 4. Risk Assessment & Threat Signals Integration ───────────────
            threat_score = threat_result.overall_threat_score if threat_result else 0.0
            if threat_result:
                for tf in threat_result.findings:
                    reasons.append(f"Threat Finding [{tf.threat_type.value}]: {tf.title} ({tf.severity.value})")
                for corr in threat_result.correlations:
                    reasons.append(f"Threat Correlation: {corr.title} (Score: {corr.threat_score})")
                if threat_result.incomplete_analysis:
                    reasons.append("Threat analysis incomplete: one or more detectors failed or timed out.")

            risk = RiskScoringEngine.calculate_score(request, threat_score=threat_score)
            for factor in risk.factors:
                reasons.append(f"Risk [{factor.factor_name} +{factor.impact}]: {factor.description}")

            # ── 5. Approval & Decision Precedence ───────────────────────────────
            # ASK_HUMAN triggered if:
            #   a) Policy required approval, OR
            #   b) Risk score exceeds max permitted risk from permissions, OR
            #   c) Threat analysis detected CRITICAL threat with high score
            critical_threat_detected = (
                threat_result is not None
                and (threat_result.highest_severity == ThreatSeverity.CRITICAL or threat_score >= 85.0)
            )

            requires_approval = (
                policy_result.decision == Decision.ASK_HUMAN
                or policy_result.requires_approval
                or risk.score > effective_perms.max_permitted_risk_score
                or critical_threat_detected
            )

            if requires_approval and policy_result.decision != Decision.BLOCK:
                approval_id = uuid.uuid4()
                if critical_threat_detected:
                    reasons.append(
                        f"Critical threat signal detected (score: {threat_score}): human approval required."
                    )
                elif risk.score > effective_perms.max_permitted_risk_score:
                    reasons.append(
                        f"Risk score {risk.score} exceeds agent permitted threshold ({effective_perms.max_permitted_risk_score}): human approval required."
                    )

                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return SecurityDecision(
                    request_id=request.request_id,
                    decision=Decision.ASK_HUMAN,
                    risk_score=risk.score,
                    risk_level=risk.level,
                    reasons=reasons,
                    matched_policies=matched_policies,
                    policy_version=policy_result.effective_version,
                    approval_required=True,
                    approval_id=approval_id,
                    approval_timeout_seconds=300,
                    evaluated_at=datetime.now(UTC),
                    evaluation_duration_ms=round(duration_ms, 2),
                )

            # ── 6. Affirmative Authorization (ALLOW) ───────────────────────────
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            reasons.append(f"Action authorized under {effective_perms.max_permitted_risk_score} risk threshold.")

            return SecurityDecision(
                request_id=request.request_id,
                decision=Decision.ALLOW,
                risk_score=risk.score,
                risk_level=risk.level,
                reasons=reasons,
                matched_policies=matched_policies,
                policy_version=policy_result.effective_version,
                approval_required=False,
                evaluated_at=datetime.now(UTC),
                evaluation_duration_ms=round(duration_ms, 2),
            )

        except Exception as exc:  # noqa: BLE001
            # FAIL-CLOSED GUARANTEE: Never fail open on unexpected errors
            logger.error("Security evaluation encountered unexpected error, failing closed: %s", exc)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return SecurityDecision(
                request_id=request.request_id,
                decision=Decision.BLOCK,
                risk_score=100.0,
                risk_level=RiskLevel.CRITICAL,
                reasons=["Security evaluation failed closed due to an internal error."],
                matched_policies=[],
                policy_version=1,
                approval_required=False,
                evaluated_at=datetime.now(UTC),
                evaluation_duration_ms=round(duration_ms, 2),
            )

    def _build_fail_decision(
        self,
        request: ActionRequest,
        reason: str,
        start_time: float,
    ) -> SecurityDecision:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return SecurityDecision(
            request_id=request.request_id,
            decision=Decision.BLOCK,
            risk_score=90.0,
            risk_level=RiskLevel.CRITICAL,
            reasons=[reason],
            matched_policies=[],
            policy_version=1,
            approval_required=False,
            evaluated_at=datetime.now(UTC),
            evaluation_duration_ms=round(duration_ms, 2),
        )


def compute_canonical_request_hash(request: ActionRequest) -> str:
    """Compute SHA256 cryptographic hash of canonical action request representation."""
    payload = {
        "request_id": str(request.request_id),
        "agent_id": str(request.agent_id),
        "tool_name": request.tool_name.lower().strip(),
        "operation": (request.operation or "").lower().strip(),
        "resource": (request.resource or "").lower().strip(),
    }
    serialized = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
