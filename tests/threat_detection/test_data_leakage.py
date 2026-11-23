"""
Tests for Data Leakage & Secret Redaction Detector (Phase 5).
"""

import uuid
import pytest
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.contracts.threat import ThreatCategory, ThreatSeverity
from agentshield.threat_detection.analyzers.content_analyzer import ContentAnalyzer
from agentshield.threat_detection.detectors.data_leakage import DataLeakageDetector


def _req(args: dict, resource: str | None = None, tool: str = "http_client", cat: ToolCategory = ToolCategory.NETWORK) -> ActionRequest:
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        integration_type=IntegrationType.API,
        tool_name=tool,
        tool_category=cat,
        operation="post",
        arguments=args,
        resource=resource,
    )


class TestDataLeakageDetector:
    def setup_method(self):
        self.detector = DataLeakageDetector()

    def test_openai_api_key_detected_and_redacted(self):
        secret = "sk-proj-abc1234567890def1234567890ghij"
        req = _req({"headers": {"Authorization": f"Bearer {secret}"}})
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert findings[0].threat_type == ThreatCategory.DATA_LEAKAGE
        # Guarantee raw secret is never present in evidence
        evidence_str = str(findings[0].evidence)
        assert secret not in evidence_str

    def test_aws_access_key_detected(self):
        req = _req({"aws_key": "AKIA1234567890ABCDEF"})
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert "Cleartext Credentials Detected" in findings[0].title
        assert "AKIA1234567890ABCDEF" not in str(findings[0].evidence)

    def test_rsa_private_key_detected(self):
        priv_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        req = _req({"key_pem": priv_key}, tool="upload_file", cat=ToolCategory.FILE_SYSTEM)
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert "MIIEow" not in str(findings[0].evidence)

    def test_sensitive_credential_file_targeted(self):
        req = _req({}, resource="/home/user/.ssh/id_rsa", tool="file_reader", cat=ToolCategory.FILE_SYSTEM)
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Credential Store Targeted" in f.title for f in findings)
        assert findings[0].severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL)

    def test_env_file_targeted(self):
        req = _req({}, resource="e:/project/.env", tool="file_reader", cat=ToolCategory.FILE_SYSTEM)
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any(".env" in f.title or "Credential Store Targeted" in f.title for f in findings)

    def test_benign_arguments_no_secrets(self):
        req = _req({"name": "Alice", "role": "developer", "age": 30})
        findings = self.detector.analyze(req)
        assert len(findings) == 0

    def test_content_analyzer_redact_string(self):
        raw = "My OpenAI key is sk-proj-1234567890abcdefghij and AWS is AKIA0987654321ABCDEF."
        redacted, detected = ContentAnalyzer.redact_string(raw)
        assert "sk-proj-1234567890abcdefghij" not in redacted
        assert "AKIA0987654321ABCDEF" not in redacted
        assert "OPENAI_API_KEY" in detected
        assert "AWS_ACCESS_KEY" in detected
