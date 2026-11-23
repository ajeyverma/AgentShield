"""
Tests for Behavioral Anomaly Detector (Phase 5).
"""

import uuid
from datetime import UTC, datetime, timedelta
import pytest
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.contracts.threat import ThreatCategory, ThreatSeverity
from agentshield.threat_detection.detectors.behavioral import BehavioralAnomalyDetector


def _req(agent_id: uuid.UUID, tool: str = "read_file", op: str = "read") -> ActionRequest:
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=agent_id,
        user_id=uuid.uuid4(),
        integration_type=IntegrationType.API,
        tool_name=tool,
        tool_category=ToolCategory.FILE_SYSTEM,
        operation=op,
        arguments={"path": "/workspace/doc.txt"},
    )


class TestBehavioralAnomalyDetector:
    def setup_method(self):
        self.detector = BehavioralAnomalyDetector()

    def test_new_agent_without_baseline_no_false_positives(self):
        agent_id = uuid.uuid4()
        req = _req(agent_id)
        findings = self.detector.analyze(req, history=[])
        assert len(findings) == 0

    def test_burst_frequency_spike_detected(self):
        agent_id = uuid.uuid4()
        user_id = str(uuid.uuid4())
        req = _req(agent_id)
        req.user_id = uuid.UUID(user_id)

        now = datetime.now(UTC)
        # Create 35 recent events in last 30 seconds
        history = [
            {
                "agent_id": str(agent_id),
                "user_id": user_id,
                "tool_name": "list_files",
                "operation": "list",
                "decision": "ALLOW",
                "created_at": now - timedelta(seconds=i),
            }
            for i in range(35)
        ]

        findings = self.detector.analyze(req, history=history)
        assert len(findings) >= 1
        assert any("Request Rate Spike" in f.title for f in findings)

    def test_repeated_consecutive_denials_detected(self):
        agent_id = uuid.uuid4()
        user_id = str(uuid.uuid4())
        req = _req(agent_id)
        req.user_id = uuid.UUID(user_id)

        now = datetime.now(UTC)
        history = [
            {
                "agent_id": str(agent_id),
                "user_id": user_id,
                "tool_name": "access_database",
                "decision": "BLOCK",
                "created_at": now - timedelta(minutes=5),
            },
            {
                "agent_id": str(agent_id),
                "user_id": user_id,
                "tool_name": "access_database",
                "decision": "BLOCK",
                "created_at": now - timedelta(minutes=3),
            },
            {
                "agent_id": str(agent_id),
                "user_id": user_id,
                "tool_name": "access_database",
                "decision": "BLOCK",
                "created_at": now - timedelta(minutes=1),
            },
        ]

        findings = self.detector.analyze(req, history=history)
        assert len(findings) >= 1
        assert any("Repeated Security Authorization Denials" in f.title for f in findings)

    def test_suspicious_sequence_read_then_egress(self):
        agent_id = uuid.uuid4()
        user_id = str(uuid.uuid4())
        req = ActionRequest(
            tenant_id=uuid.uuid4(),
            agent_id=agent_id,
            user_id=uuid.UUID(user_id),
            integration_type=IntegrationType.API,
            tool_name="http_post",
            tool_category=ToolCategory.NETWORK,
            operation="post",
            arguments={"url": "https://api.external.com/upload"},
        )

        now = datetime.now(UTC)
        history = [
            {
                "agent_id": str(agent_id),
                "user_id": user_id,
                "tool_name": "read_file",
                "operation": "read",
                "decision": "ALLOW",
                "created_at": now - timedelta(seconds=2),
            }
        ]

        findings = self.detector.analyze(req, history=history)
        assert len(findings) >= 1
        assert any("High-Risk Action Sequence" in f.title for f in findings)

    def test_tenant_isolation_ignores_other_agents(self):
        agent_id = uuid.uuid4()
        other_agent_id = uuid.uuid4()
        req = _req(agent_id)

        now = datetime.now(UTC)
        history = [
            {
                "agent_id": str(other_agent_id),
                "tool_name": "access_db",
                "decision": "BLOCK",
                "created_at": now,
            }
            for _ in range(10)
        ]

        findings = self.detector.analyze(req, history=history)
        # Other agent's blocks must not trigger false anomaly on this agent
        assert len(findings) == 0
