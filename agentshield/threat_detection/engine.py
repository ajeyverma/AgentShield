"""
AgentShield AI — Threat Detection Engine Facade.
"""

from __future__ import annotations

from agentshield.threat_detection.coordinator import ThreatDetectionCoordinator
from agentshield.threat_detection.registry import DetectorRegistry

# Global singleton coordinator
default_registry = DetectorRegistry()
threat_coordinator = ThreatDetectionCoordinator(registry=default_registry)
