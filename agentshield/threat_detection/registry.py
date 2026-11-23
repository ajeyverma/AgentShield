"""
AgentShield AI — Detector Registry (Phase 5).
"""

from __future__ import annotations

from typing import Sequence

from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.detectors import DEFAULT_DETECTORS


class DetectorRegistry:
    """Registry maintaining active threat detectors."""

    def __init__(self, initial_detectors: Sequence[BaseDetector] | None = None) -> None:
        self._detectors: dict[str, BaseDetector] = {}
        for d in (initial_detectors or DEFAULT_DETECTORS):
            self.register(d)

    def register(self, detector: BaseDetector) -> None:
        self._detectors[detector.detector_id] = detector

    def unregister(self, detector_id: str) -> bool:
        if detector_id in self._detectors:
            del self._detectors[detector_id]
            return True
        return False

    def get(self, detector_id: str) -> BaseDetector | None:
        return self._detectors.get(detector_id)

    def list_all(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def list_active(self) -> list[BaseDetector]:
        return [d for d in self._detectors.values() if d.is_active]
