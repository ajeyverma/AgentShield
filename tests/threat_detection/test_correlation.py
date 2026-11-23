"""
Tests for Threat Correlation Engine (Phase 5).
"""

import uuid
import pytest
from agentshield.contracts.threat import (
    FindingStatus,
    ThreatCategory,
    ThreatConfidence,
    ThreatFinding,
    ThreatSeverity,
)
from agentshield.threat_detection.correlation import ThreatCorrelationEngine


def _finding(cat: ThreatCategory, sev: ThreatSeverity, risk: float, title: str) -> ThreatFinding:
    return ThreatFinding(
        finding_id=uuid.uuid4(),
        request_id=uuid.uuid4(),
        user_id="user-1",
        agent_id="agent-1",
        detector_id="DET-TEST",
        threat_type=cat,
        title=title,
        description=f"Description for {title}",
        severity=sev,
        confidence=ThreatConfidence.HIGH,
        risk_contribution=risk,
    )


class TestThreatCorrelationEngine:
    def test_empty_findings_returns_zero(self):
        corrs, score, sev = ThreatCorrelationEngine.correlate("agent-1", [])
        assert corrs == []
        assert score == 0.0
        assert sev == ThreatSeverity.LOW

    def test_prompt_injection_plus_credential_access_correlation(self):
        f1 = _finding(ThreatCategory.PROMPT_INJECTION, ThreatSeverity.HIGH, 75.0, "Instruction Override")
        f2 = _finding(ThreatCategory.DATA_LEAKAGE, ThreatSeverity.HIGH, 70.0, "API Key Exposed")

        corrs, score, sev = ThreatCorrelationEngine.correlate("agent-1", [f1, f2])
        assert len(corrs) >= 1
        assert "Prompt Injection with Credential Harvest" in corrs[0].title
        assert corrs[0].overall_severity == ThreatSeverity.CRITICAL
        assert score >= 95.0
        assert sev == ThreatSeverity.CRITICAL

    def test_prompt_injection_plus_dangerous_command_correlation(self):
        f1 = _finding(ThreatCategory.PROMPT_INJECTION, ThreatSeverity.CRITICAL, 85.0, "Jailbreak")
        f2 = _finding(ThreatCategory.DANGEROUS_COMMAND, ThreatSeverity.CRITICAL, 100.0, "Catastrophic Deletion")

        corrs, score, sev = ThreatCorrelationEngine.correlate("agent-1", [f1, f2])
        assert len(corrs) >= 1
        assert "Attack Chain: Prompt Injection Driving Dangerous Command" in corrs[0].title
        assert score == 100.0
        assert sev == ThreatSeverity.CRITICAL

    def test_filesystem_traversal_plus_network_egress(self):
        f1 = _finding(ThreatCategory.FILESYSTEM, ThreatSeverity.HIGH, 80.0, "Directory Traversal")
        f2 = _finding(ThreatCategory.SUSPICIOUS_NETWORK, ThreatSeverity.HIGH, 75.0, "SSRF Metadata")

        corrs, score, sev = ThreatCorrelationEngine.correlate("agent-1", [f1, f2])
        assert len(corrs) >= 1
        assert "Filesystem Traversal Followed by Network Egress" in corrs[0].title
        assert score >= 90.0

    def test_score_boundaries_remain_within_zero_to_hundred(self):
        many_findings = [
            _finding(ThreatCategory.SUSPICIOUS_ACTIVITY, ThreatSeverity.CRITICAL, 99.0, f"Anomaly {i}")
            for i in range(10)
        ]
        _, score, sev = ThreatCorrelationEngine.correlate("agent-1", many_findings)
        assert 0.0 <= score <= 100.0
        assert sev == ThreatSeverity.CRITICAL
