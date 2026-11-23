"""
AgentShield AI — Security Engine Export (Phase 4).
"""

from agentshield.security.evaluator import (
    SecurityDecisionEngine,
    compute_canonical_request_hash,
)
from agentshield.security.permissions import (
    AgentPermissions,
    PermissionEvaluator,
    PermissionResult,
)
from agentshield.security.policy_engine import (
    PolicyEngine,
    PolicyEvaluationResult,
)
from agentshield.security.risk_scoring import (
    RiskAssessment,
    RiskFactor,
    RiskScoringEngine,
)

# Global default decision engine
security_engine = SecurityDecisionEngine()

__all__ = [
    "SecurityDecisionEngine",
    "security_engine",
    "compute_canonical_request_hash",
    "AgentPermissions",
    "PermissionEvaluator",
    "PermissionResult",
    "PolicyEngine",
    "PolicyEvaluationResult",
    "RiskScoringEngine",
    "RiskAssessment",
    "RiskFactor",
]
