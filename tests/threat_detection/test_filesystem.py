"""
Tests for Filesystem Threat Detector (Phase 5).
"""

import uuid
import pytest
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.contracts.threat import ThreatCategory, ThreatSeverity
from agentshield.threat_detection.detectors.filesystem import FilesystemThreatDetector


def _req(resource: str, op: str = "read", tool: str = "read_file") -> ActionRequest:
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        integration_type=IntegrationType.API,
        tool_name=tool,
        tool_category=ToolCategory.FILE_SYSTEM,
        operation=op,
        arguments={"path": resource},
        resource=resource,
    )


class TestFilesystemThreatDetector:
    def setup_method(self):
        self.detector = FilesystemThreatDetector()

    def test_path_traversal_detection(self):
        req = _req("../../etc/passwd")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Directory Traversal" in f.title for f in findings)
        assert any(f.severity == ThreatSeverity.CRITICAL for f in findings)

    def test_restricted_linux_system_dir(self):
        req = _req("/etc/shadow")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Restricted System Directory" in f.title for f in findings)

    def test_restricted_windows_system_dir(self):
        req = _req("C:\\Windows\\System32\\config\\SAM")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Restricted System Directory" in f.title for f in findings)

    def test_destructive_file_deletion(self):
        req = _req("/workspace/project/cache", op="delete", tool="delete_file")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Destructive File Operation" in f.title for f in findings)
        assert any(f.severity == ThreatSeverity.HIGH for f in findings)

    def test_safe_workspace_file_read(self):
        req = _req("/workspace/project/main.py", op="read", tool="read_file")
        findings = self.detector.analyze(req)
        assert len(findings) == 0
