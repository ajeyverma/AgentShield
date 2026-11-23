"""
AgentShield AI — Risk Scoring Engine (Phase 4).

Calculates a deterministic, explainable risk score (0–100) and qualitative
risk level (LOW, MEDIUM, HIGH, CRITICAL) for an incoming ActionRequest.

Guarantees:
  1. Deterministic: Given identical ActionRequest inputs, the exact same score is returned.
  2. Explainable: Every point contributing to the score is itemized as a distinct RiskFactor.
  3. No LLM in the Loop: Evaluation is based solely on static, deterministic security heuristics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import RiskLevel, ToolCategory

_SENSITIVE_RESOURCE_PATTERNS = [
    re.compile(r"password|secret|credential|token|api[_-]?key|private[_-]?key|id_rsa|\.env", re.IGNORECASE),
    re.compile(r"/etc/|/var/log|windows/system32", re.IGNORECASE),
    re.compile(r"\b(users|accounts|payments|billing|customers)\b", re.IGNORECASE),
]

_DESTRUCTIVE_OPERATIONS = {
    "delete", "remove", "drop", "truncate", "destroy", "erase", "format",
    "purge", "unlink", "kill", "terminate", "wipe", "shutdown",
}

_MODIFY_OPERATIONS = {
    "write", "create", "insert", "update", "modify", "patch", "alter",
    "append", "edit", "save", "upload", "send", "post", "put",
}


@dataclass(frozen=True)
class RiskFactor:
    """An individual contributor to the overall risk assessment."""

    factor_name: str
    impact: float
    description: str


@dataclass(frozen=True)
class RiskAssessment:
    """Complete, explainable risk analysis outcome."""

    score: float
    level: RiskLevel
    factors: list[RiskFactor] = field(default_factory=list)
    version: str = "1.0"


class RiskScoringEngine:
    """Deterministic, explainable risk assessment engine."""

    VERSION = "1.0"

    @classmethod
    def calculate_score(
        cls,
        request: ActionRequest,
        threat_score: float = 0.0,
        threat_factors: list[RiskFactor] | None = None,
    ) -> RiskAssessment:
        factors: list[RiskFactor] = []
        base_score = 0.0

        # ── 1. Tool Category Sensitivity ──────────────────────────────────────
        category = request.tool_category
        cat_val = category.value if isinstance(category, ToolCategory) else str(category)

        if category in (ToolCategory.TERMINAL, ToolCategory.CODE_EXECUTION) or "exec" in request.tool_name.lower():
            impact = 40.0
            factors.append(RiskFactor("ToolSensitivity", impact, "Tool has arbitrary shell/code execution capability."))
            base_score += impact
        elif category == ToolCategory.DATABASE:
            impact = 30.0
            factors.append(RiskFactor("ToolSensitivity", impact, "Tool accesses backend database records."))
            base_score += impact
        elif category in (ToolCategory.NETWORK, ToolCategory.EXTERNAL_API):
            impact = 25.0
            factors.append(RiskFactor("ToolSensitivity", impact, "Tool interacts with external network endpoints."))
            base_score += impact
        elif category == ToolCategory.FILE_SYSTEM:
            impact = 20.0
            factors.append(RiskFactor("ToolSensitivity", impact, "Tool interacts with host filesystem."))
            base_score += impact
        elif category == ToolCategory.BROWSER:
            impact = 15.0
            factors.append(RiskFactor("ToolSensitivity", impact, "Tool automates web browser actions."))
            base_score += impact
        elif category == ToolCategory.UNKNOWN:
            impact = 35.0
            factors.append(RiskFactor("UnknownToolCategory", impact, "Tool category is unknown/unclassified."))
            base_score += impact

        # ── 2. Operation Destructiveness ──────────────────────────────────────
        op = (request.operation or "").lower().strip()
        tool = request.tool_name.lower().strip()

        if op in _DESTRUCTIVE_OPERATIONS or any(d in tool for d in ("delete", "remove", "drop", "truncate")):
            impact = 35.0
            factors.append(RiskFactor("DestructiveOperation", impact, f"Destructive operation detected: '{op or tool}'."))
            base_score += impact
        elif op in _MODIFY_OPERATIONS or any(m in tool for m in ("write", "update", "insert")):
            impact = 15.0
            factors.append(RiskFactor("StateModifyingOperation", impact, f"State-modifying operation: '{op or tool}'."))
            base_score += impact

        # ── 3. Resource Sensitivity ───────────────────────────────────────────
        target_resource = request.resource or str(request.arguments.get("path") or request.arguments.get("url") or "")
        if target_resource:
            for pattern in _SENSITIVE_RESOURCE_PATTERNS:
                if pattern.search(target_resource):
                    impact = 30.0
                    factors.append(RiskFactor("SensitiveResourceTarget", impact, f"Target resource references sensitive path or keywords: '{target_resource}'."))
                    base_score += impact
                    break
        else:
            # Missing resource context penalty
            if op in _DESTRUCTIVE_OPERATIONS or op in _MODIFY_OPERATIONS:
                impact = 15.0
                factors.append(RiskFactor("MissingResourceContext", impact, "Action modifies state without explicitly specifying target resource."))
                base_score += impact

        # ── 4. High-Privilege Requested Scopes ───────────────────────────────
        if request.requested_permissions:
            high_priv_count = sum(1 for p in request.requested_permissions if p.lower() in ("admin", "root", "write", "execute", "all"))
            if high_priv_count > 0:
                impact = min(20.0, high_priv_count * 10.0)
                factors.append(RiskFactor("ElevatedRequestedPermissions", impact, f"Requested elevated scopes: {request.requested_permissions}."))
                base_score += impact

        # ── 5. Threat Intelligence & Anomaly Signal Contribution ──────────────
        if threat_score > 0.0:
            impact = min(40.0, round(threat_score * 0.4, 1))
            factors.append(
                RiskFactor(
                    "ThreatDetectionSignal",
                    impact,
                    f"Threat detection engine flagged suspicious activity (threat score: {threat_score}).",
                )
            )
            base_score += impact

        if threat_factors:
            for tf in threat_factors:
                factors.append(tf)
                base_score += tf.impact

        # ── 6. Clamping and Level Assignment ─────────────────────────────────
        final_score = max(0.0, min(100.0, round(base_score, 1)))

        if final_score < 25.0:
            level = RiskLevel.LOW
        elif final_score < 50.0:
            level = RiskLevel.MEDIUM
        elif final_score < 75.0:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        return RiskAssessment(
            score=final_score,
            level=level,
            factors=factors,
            version=cls.VERSION,
        )
