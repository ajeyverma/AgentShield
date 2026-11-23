"""
AgentShield AI — Filesystem Threat Detector (Phase 5).

Analyzes filesystem action requests for path traversal, restricted OS directories,
and mass destructive operations.
"""

from __future__ import annotations

import os
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import ToolCategory
from agentshield.contracts.provenance import ProvenanceContext
from agentshield.contracts.threat import (
    ThreatCategory,
    ThreatConfidence,
    ThreatFinding,
    ThreatSeverity,
)
from agentshield.threat_detection.analyzers.action_analyzer import ActionAnalyzer
from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.rules.filesystem_rules import (
    DESTRUCTIVE_FS_OPERATIONS,
    RESTRICTED_SYSTEM_DIRS,
    TRAVERSAL_PATTERN,
)


class FilesystemThreatDetector(BaseDetector):
    """Detector for filesystem attacks, traversal, and unauthorized directory tampering."""

    detector_id = "DET-FS-003"
    detector_name = "Filesystem Security & Traversal Detector"
    detector_version = "1.0.0"
    category = ThreatCategory.FILESYSTEM

    def analyze(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        user_id = str(request.user_id or "unknown")
        agent_id = str(request.agent_id)

        target = ActionAnalyzer.extract_target_resource(request)
        op = (request.operation or "").lower()
        tool = request.tool_name.lower()

        # 1. Directory Traversal Checks
        if target and TRAVERSAL_PATTERN.search(target):
            findings.append(
                ThreatFinding(
                    request_id=request.request_id,
                    user_id=user_id,
                    agent_id=agent_id,
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    threat_type=self.category,
                    title="Filesystem Threat: Directory Traversal Sequence Detected",
                    description=f"Path traversal sequence ('../' or '..\\') detected in target path: '{target}'.",
                    severity=ThreatSeverity.CRITICAL,
                    confidence=ThreatConfidence.HIGH,
                    risk_contribution=90.0,
                    evidence={"target_path": target, "pattern": "directory_traversal"},
                    affected_resource=target,
                    source_provenance=provenance,
                    recommended_action="Block path traversal attempt and confine agent to authorized workspace root.",
                )
            )

        # 2. Restricted System Directories Access
        if target:
            # Safe path normalization (without dereferencing symlinks or disk access)
            normalized = os.path.normpath(target).replace("\\", "/").lower()
            for restricted in RESTRICTED_SYSTEM_DIRS:
                r_norm = restricted.replace("\\", "/").lower()
                if normalized == r_norm or normalized.startswith(r_norm + "/") or r_norm in normalized:
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Filesystem Threat: Restricted System Directory Access",
                            description=f"Action targets protected OS directory or sensitive configuration: '{target}'.",
                            severity=ThreatSeverity.CRITICAL,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=95.0,
                            evidence={"target_path": target, "matched_restricted_dir": restricted},
                            affected_resource=target,
                            source_provenance=provenance,
                            recommended_action="Enforce strict isolation; deny agent access to host system directories.",
                        )
                    )
                    break

        # 3. Destructive Filesystem Operations
        is_fs_tool = request.tool_category == ToolCategory.FILE_SYSTEM or "file" in tool or "fs" in tool
        if is_fs_tool:
            is_destructive = op in DESTRUCTIVE_FS_OPERATIONS or any(d in tool for d in ("delete", "remove", "wipe", "format"))
            if is_destructive:
                findings.append(
                    ThreatFinding(
                        request_id=request.request_id,
                        user_id=user_id,
                        agent_id=agent_id,
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                        threat_type=self.category,
                        title="Filesystem Threat: Destructive File Operation Requested",
                        description=f"Operation '{op or tool}' performs irreversible deletion or wiping on resource '{target}'.",
                        severity=ThreatSeverity.HIGH,
                        confidence=ThreatConfidence.HIGH,
                        risk_contribution=75.0,
                        evidence={"operation": op or tool, "resource": target},
                        affected_resource=target,
                        source_provenance=provenance,
                        recommended_action="Require human supervisor authorization before executing destructive deletions.",
                    )
                )

        return findings
