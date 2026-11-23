"""
AgentShield AI — Threat Detection Exceptions.
"""

from __future__ import annotations


class ThreatDetectionError(Exception):
    """Base exception for all threat detection operations."""

    def __init__(self, message: str, detector_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detector_id = detector_id


class DetectorExecutionError(ThreatDetectionError):
    """Raised when an individual detector encounters an unhandled runtime error."""


class IncompleteAnalysisError(ThreatDetectionError):
    """Raised when threat evaluation could not complete all registered checks."""
