"""
AgentShield AI — Threat Detection Coordinator (Phase 5).

Coordinates detector execution, aggregates findings, manages timing,
isolates failures, and invokes threat correlation.
"""

from __future__ import annotations

import logging
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.provenance import ProvenanceContext
from agentshield.contracts.threat import ThreatAnalysisResult, ThreatFinding, ThreatSeverity
from agentshield.threat_detection.correlation import ThreatCorrelationEngine
from agentshield.threat_detection.registry import DetectorRegistry

logger = logging.getLogger("agentshield.threat_detection.coordinator")


class ThreatDetectionCoordinator:
    """Central orchestrator for all registered threat detectors."""

    def __init__(self, registry: DetectorRegistry | None = None) -> None:
        self.registry = registry or DetectorRegistry()

    def analyze_action(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> ThreatAnalysisResult:
        """Run all active threat detectors and synthesize an authoritative ThreatAnalysisResult."""
        all_findings: list[ThreatFinding] = []
        execution_times: dict[str, float] = {}
        analysis_errors: list[str] = []
        incomplete_analysis = False

        # Execute each detector under isolated timing and exception bounds
        for detector in self.registry.list_active():
            findings, duration_ms, err = detector.safe_analyze(
                request=request,
                provenance=provenance,
                history=history,
            )
            execution_times[detector.detector_id] = duration_ms
            if err:
                analysis_errors.append(err)
                incomplete_analysis = True
            else:
                all_findings.extend(findings)

        # Correlate findings across detectors
        correlations, overall_score, highest_sev = ThreatCorrelationEngine.correlate(
            agent_id=str(request.agent_id),
            findings=all_findings,
            session_id=str(request.session_id) if request.session_id else None,
        )

        # If analysis failed and no findings, fail-closed metadata is attached
        if incomplete_analysis and not all_findings:
            overall_score = max(overall_score, 25.0)  # non-zero risk for incomplete analysis

        return ThreatAnalysisResult(
            request_id=request.request_id,
            agent_id=str(request.agent_id),
            findings=all_findings,
            correlations=correlations,
            overall_threat_score=overall_score,
            highest_severity=highest_sev,
            detector_execution_times_ms=execution_times,
            incomplete_analysis=incomplete_analysis,
            analysis_errors=analysis_errors,
        )
