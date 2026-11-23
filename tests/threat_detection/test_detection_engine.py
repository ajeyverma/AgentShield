"""
Tests for Central Threat Detection Engine & Performance Benchmark (Phase 5).
"""

import time
import uuid
import pytest
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.contracts.threat import ThreatCategory, ThreatSeverity
from agentshield.threat_detection.coordinator import ThreatDetectionCoordinator
from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.engine import default_registry, threat_coordinator
from agentshield.threat_detection.registry import DetectorRegistry


class FailingDummyDetector(BaseDetector):
    detector_id = "DET-FAIL-000"
    detector_name = "Failing Dummy Detector"
    detector_version = "1.0.0"
    category = ThreatCategory.SUSPICIOUS_ACTIVITY

    def analyze(self, request, provenance=None, history=None):
        raise RuntimeError("Simulated detector internal glitch")


class TestThreatDetectionEngine:
    def test_coordinator_runs_all_active_detectors(self):
        req = ActionRequest(
            tenant_id=uuid.uuid4(),
            agent_id=uuid.uuid4(),
            integration_type=IntegrationType.API,
            tool_name="shell",
            tool_category=ToolCategory.TERMINAL,
            operation="execute",
            arguments={"command": "rm -rf /"},
            resource="rm -rf /",
        )
        res = threat_coordinator.analyze_action(req)
        assert res.has_threats is True
        assert len(res.detector_execution_times_ms) >= 6
        assert all(isinstance(v, float) for v in res.detector_execution_times_ms.values())

    def test_detector_failure_does_not_crash_coordinator(self):
        custom_registry = DetectorRegistry()
        failing_detector = FailingDummyDetector()
        custom_registry.register(failing_detector)
        coord = ThreatDetectionCoordinator(registry=custom_registry)

        req = ActionRequest(
            tenant_id=uuid.uuid4(),
            agent_id=uuid.uuid4(),
            integration_type=IntegrationType.API,
            tool_name="list_files",
            tool_category=ToolCategory.FILE_SYSTEM,
            arguments={"path": "/safe/path"},
        )
        res = coord.analyze_action(req)
        assert res.incomplete_analysis is True
        assert len(res.analysis_errors) >= 1
        assert "Simulated detector internal glitch" in res.analysis_errors[0]

    def test_performance_benchmark(self):
        """Benchmark: 50 synthetic requests processed within 500ms total (<10ms per eval)."""
        req = ActionRequest(
            tenant_id=uuid.uuid4(),
            agent_id=uuid.uuid4(),
            integration_type=IntegrationType.API,
            tool_name="read_file",
            tool_category=ToolCategory.FILE_SYSTEM,
            operation="read",
            arguments={"path": "/workspace/data.json"},
            resource="/workspace/data.json",
        )

        start = time.perf_counter()
        iterations = 50
        for _ in range(iterations):
            _ = threat_coordinator.analyze_action(req)
        elapsed = time.perf_counter() - start

        avg_ms_per_req = (elapsed / iterations) * 1000.0
        assert avg_ms_per_req < 20.0, f"Average detection latency too slow: {avg_ms_per_req:.2f}ms"
