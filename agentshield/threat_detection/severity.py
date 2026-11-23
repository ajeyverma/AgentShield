"""
AgentShield AI — Threat Severity Definitions & Helpers.
"""

from __future__ import annotations

from agentshield.contracts.threat import ThreatSeverity

SEVERITY_WEIGHTS: dict[ThreatSeverity, float] = {
    ThreatSeverity.LOW: 15.0,
    ThreatSeverity.MEDIUM: 40.0,
    ThreatSeverity.HIGH: 70.0,
    ThreatSeverity.CRITICAL: 100.0,
}


def score_to_severity(score: float) -> ThreatSeverity:
    """Map numeric risk/threat score (0-100) to ThreatSeverity."""
    if score >= 85.0:
        return ThreatSeverity.CRITICAL
    if score >= 60.0:
        return ThreatSeverity.HIGH
    if score >= 30.0:
        return ThreatSeverity.MEDIUM
    return ThreatSeverity.LOW
