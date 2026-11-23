"""
AgentShield AI — Dangerous Command Analyzer (Phase 5).

Static analysis of terminal and shell commands for catastrophic operations,
privilege escalation, defense evasion, and encoded commands without executing them.
"""

from __future__ import annotations

from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.provenance import ProvenanceContext
from agentshield.contracts.threat import (
    ThreatCategory,
    ThreatConfidence,
    ThreatFinding,
    ThreatSeverity,
)
from agentshield.threat_detection.analyzers.content_analyzer import ContentAnalyzer
from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.rules.command_rules import (
    CATASTROPHIC_PATTERNS,
    DEFENSE_EVASION_PATTERNS,
    ENCODED_EXECUTION_PATTERNS,
    PRIVILEGE_ESCALATION_PATTERNS,
    REVERSE_SHELL_PATTERNS,
)


class CommandAnalysisDetector(BaseDetector):
    """Static detector for dangerous terminal and shell command execution."""

    detector_id = "DET-CMD-004"
    detector_name = "Static Command & Shell Analysis Detector"
    detector_version = "1.0.0"
    category = ThreatCategory.DANGEROUS_COMMAND

    def analyze(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        user_id = str(request.user_id or "unknown")
        agent_id = str(request.agent_id)

        # Extract command strings safely
        cmd_candidates: list[str] = []
        args = request.arguments or {}
        for key in ("command", "cmd", "script", "exec", "line"):
            if key in args and isinstance(args[key], str) and args[key].strip():
                cmd_candidates.append(args[key].strip())

        if request.resource and any(sh in request.tool_name.lower() for sh in ("shell", "terminal", "exec", "bash", "sh", "cmd", "powershell")):
            cmd_candidates.append(request.resource.strip())

        for raw_cmd in cmd_candidates:
            # Redact any embedded secrets in the command string for evidence safety
            redacted_cmd, _ = ContentAnalyzer.redact_string(raw_cmd)

            # 1. Catastrophic Destructive Commands
            for pat in CATASTROPHIC_PATTERNS:
                if pat.search(raw_cmd):
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Dangerous Command: Catastrophic System Destruction",
                            description="Catastrophic command pattern detected (e.g. root filesystem deletion, disk format, fork bomb).",
                            severity=ThreatSeverity.CRITICAL,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=100.0,
                            evidence={"redacted_command": redacted_cmd, "pattern_type": "catastrophic_deletion"},
                            affected_resource=raw_cmd[:80],
                            source_provenance=provenance,
                            recommended_action="Immediately terminate agent action and block catastrophic execution.",
                        )
                    )
                    break

            # 2. Reverse Shell & Outbound Tunneling
            for pat in REVERSE_SHELL_PATTERNS:
                if pat.search(raw_cmd):
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Dangerous Command: Reverse Shell Execution Attempt",
                            description="Reverse interactive shell or tunneling payload detected in command arguments.",
                            severity=ThreatSeverity.CRITICAL,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=100.0,
                            evidence={"redacted_command": redacted_cmd, "pattern_type": "reverse_shell"},
                            affected_resource=raw_cmd[:80],
                            source_provenance=provenance,
                            recommended_action="Block execution and quarantine agent session immediately.",
                        )
                    )
                    break

            # 3. Privilege Escalation Commands
            for pat in PRIVILEGE_ESCALATION_PATTERNS:
                if pat.search(raw_cmd):
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Dangerous Command: Privilege Escalation Attempt",
                            description="Command attempts to acquire root/administrator privileges or modify permission boundaries.",
                            severity=ThreatSeverity.HIGH,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=85.0,
                            evidence={"redacted_command": redacted_cmd, "pattern_type": "privilege_escalation"},
                            affected_resource=raw_cmd[:80],
                            source_provenance=provenance,
                            recommended_action="Deny elevated permissions and audit agent credentials.",
                        )
                    )
                    break

            # 4. Defense Evasion Commands
            for pat in DEFENSE_EVASION_PATTERNS:
                if pat.search(raw_cmd):
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Dangerous Command: Security Defense Evasion",
                            description="Command attempts to disable firewall, endpoint protection, or security controls.",
                            severity=ThreatSeverity.CRITICAL,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=95.0,
                            evidence={"redacted_command": redacted_cmd, "pattern_type": "defense_evasion"},
                            affected_resource=raw_cmd[:80],
                            source_provenance=provenance,
                            recommended_action="Block command and alert security operations of evasion attempt.",
                        )
                    )
                    break

            # 5. Encoded Command Execution
            for pat in ENCODED_EXECUTION_PATTERNS:
                if pat.search(raw_cmd):
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Dangerous Command: Obfuscated Encoded Shell Execution",
                            description="Encoded payload execution detected (e.g., powershell -enc or base64 piped to shell).",
                            severity=ThreatSeverity.HIGH,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=80.0,
                            evidence={"redacted_command": redacted_cmd, "pattern_type": "encoded_execution"},
                            affected_resource=raw_cmd[:80],
                            source_provenance=provenance,
                            recommended_action="Require decoded script inspection before authorization.",
                        )
                    )
                    break

        return findings
