"""
Tests for Network Threat Detector (Phase 5).
"""

import uuid
import pytest
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.contracts.threat import ThreatCategory, ThreatSeverity
from agentshield.threat_detection.detectors.network import NetworkThreatDetector


def _req(target: str, tool: str = "http_request") -> ActionRequest:
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        integration_type=IntegrationType.API,
        tool_name=tool,
        tool_category=ToolCategory.NETWORK,
        operation="get",
        arguments={"url": target},
        resource=target,
    )


class TestNetworkThreatDetector:
    def setup_method(self):
        self.detector = NetworkThreatDetector()

    def test_cloud_metadata_ip_ssrf(self):
        req = _req("http://169.254.169.254/latest/meta-data/")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Cloud Metadata Service SSRF" in f.title for f in findings)
        assert findings[0].severity == ThreatSeverity.CRITICAL

    def test_cloud_metadata_hostname_ssrf(self):
        req = _req("http://metadata.google.internal/computeMetadata/v1/")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Cloud Metadata Service SSRF" in f.title for f in findings)

    def test_local_loopback_probing(self):
        req = _req("http://127.0.0.1:8080/admin")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Local Loopback Probing" in f.title for f in findings)

    def test_suspicious_port_irc(self):
        req = _req("http://example.com:6667")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Non-Standard Egress Port" in f.title for f in findings)

    def test_dangerous_protocol_scheme(self):
        req = _req("gopher://10.0.0.1:70/1")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Dangerous Protocol Scheme" in f.title for f in findings)

    def test_approved_legitimate_url(self):
        req = _req("https://api.github.com/repos/openai/openai-python")
        findings = self.detector.analyze(req)
        assert len(findings) == 0
