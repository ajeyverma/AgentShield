"""
AgentShield AI — Threat Detection Package.
"""

from agentshield.threat_detection.coordinator import ThreatDetectionCoordinator
from agentshield.threat_detection.correlation import ThreatCorrelationEngine
from agentshield.threat_detection.engine import default_registry, threat_coordinator
from agentshield.threat_detection.exceptions import (
    DetectorExecutionError,
    IncompleteAnalysisError,
    ThreatDetectionError,
)
from agentshield.threat_detection.registry import DetectorRegistry
from agentshield.threat_detection.schemas import (
    DetectorMetadata,
    ThreatAnalyzeRequest,
    ThreatFindingResponse,
    ThreatFindingUpdate,
    ThreatSummaryResponse,
)

__all__ = [
    "ThreatDetectionCoordinator",
    "ThreatCorrelationEngine",
    "DetectorRegistry",
    "threat_coordinator",
    "default_registry",
    "ThreatDetectionError",
    "DetectorExecutionError",
    "IncompleteAnalysisError",
    "ThreatAnalyzeRequest",
    "ThreatFindingResponse",
    "ThreatFindingUpdate",
    "ThreatSummaryResponse",
    "DetectorMetadata",
]
