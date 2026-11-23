"""
AgentShield AI — Base Detector Interface (Phase 5).
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.provenance import ProvenanceContext
from agentshield.contracts.threat import ThreatCategory, ThreatFinding

logger = logging.getLogger("agentshield.threat_detection.detector")


class BaseDetector(ABC):
    """Abstract base class for all specialized threat detectors."""

    detector_id: str
    detector_name: str
    detector_version: str = "1.0.0"
    category: ThreatCategory
    is_active: bool = True

    @abstractmethod
    def analyze(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> list[ThreatFinding]:
        """Execute detector logic and return list of zero or more findings."""
        raise NotImplementedError

    def safe_analyze(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> tuple[list[ThreatFinding], float, str | None]:
        """Wrap analysis in strict timing and exception isolation.

        Returns (findings, duration_ms, error_message_if_any).
        """
        start = time.perf_counter()
        try:
            findings = self.analyze(request=request, provenance=provenance, history=history)
            duration_ms = (time.perf_counter() - start) * 1000.0
            return findings, round(duration_ms, 2), None
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            logger.exception("Detector '%s' failed unexpectedly: %s", self.detector_id, exc)
            return [], round(duration_ms, 2), f"Detector failure in {self.detector_id}: {str(exc)}"
