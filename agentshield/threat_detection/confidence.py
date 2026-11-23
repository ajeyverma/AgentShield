"""
AgentShield AI — Threat Confidence Definitions & Helpers.
"""

from __future__ import annotations

from agentshield.contracts.threat import ThreatConfidence

CONFIDENCE_MULTIPLIERS: dict[ThreatConfidence, float] = {
    ThreatConfidence.LOW: 0.5,
    ThreatConfidence.MEDIUM: 0.8,
    ThreatConfidence.HIGH: 1.0,
}
