"""
AgentShield AI — Network Threat Detector (Phase 5).

Analyzes network destinations, URLs, and communication requests for SSRF,
cloud metadata access, and unauthorized data egress.
"""

from __future__ import annotations

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
from agentshield.threat_detection.analyzers.destination_analyzer import DestinationAnalyzer
from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.rules.network_rules import SUSPICIOUS_SCHEMES


class NetworkThreatDetector(BaseDetector):
    """Detector for network attacks, SSRF, cloud metadata access, and egress anomalies."""

    detector_id = "DET-NET-005"
    detector_name = "Network & Destination Security Detector"
    detector_version = "1.0.0"
    category = ThreatCategory.SUSPICIOUS_NETWORK

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
        is_network = request.tool_category in (ToolCategory.NETWORK, ToolCategory.EXTERNAL_API, ToolCategory.BROWSER) or any(
            net in request.tool_name.lower() for net in ("http", "curl", "fetch", "net", "socket", "url", "browser")
        )

        if not target and not is_network:
            return findings

        # Run destination analysis
        dest = DestinationAnalyzer.analyze_destination(target)

        # 1. Cloud Metadata Service SSRF Attempt
        if dest.is_cloud_metadata:
            findings.append(
                ThreatFinding(
                    request_id=request.request_id,
                    user_id=user_id,
                    agent_id=agent_id,
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    threat_type=self.category,
                    title="Suspicious Network: Cloud Metadata Service SSRF",
                    description=f"Action requests cloud metadata endpoint (169.254.169.254 or internal metadata host): '{dest.hostname}'.",
                    severity=ThreatSeverity.CRITICAL,
                    confidence=ThreatConfidence.HIGH,
                    risk_contribution=95.0,
                    evidence={"destination": target, "hostname": dest.hostname, "is_cloud_metadata": True},
                    affected_resource=target,
                    source_provenance=provenance,
                    recommended_action="Block SSRF request and isolate instance metadata access.",
                )
            )

        # 2. Local Loopback or Private Network Probing
        elif dest.is_loopback:
            findings.append(
                ThreatFinding(
                    request_id=request.request_id,
                    user_id=user_id,
                    agent_id=agent_id,
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    threat_type=self.category,
                    title="Suspicious Network: Local Loopback Probing Detected",
                    description=f"Network request targets local loopback interface '{dest.hostname}'.",
                    severity=ThreatSeverity.HIGH,
                    confidence=ThreatConfidence.HIGH,
                    risk_contribution=80.0,
                    evidence={"destination": target, "hostname": dest.hostname, "is_loopback": True},
                    affected_resource=target,
                    source_provenance=provenance,
                    recommended_action="Enforce egress filtering and restrict localhost probing.",
                )
            )

        # 3. Suspicious Port
        if dest.is_suspicious_port:
            findings.append(
                ThreatFinding(
                    request_id=request.request_id,
                    user_id=user_id,
                    agent_id=agent_id,
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    threat_type=self.category,
                    title="Suspicious Network: Non-Standard Egress Port",
                    description=f"Destination targets non-standard or dangerous egress port {dest.port}.",
                    severity=ThreatSeverity.MEDIUM,
                    confidence=ThreatConfidence.MEDIUM,
                    risk_contribution=45.0,
                    evidence={"destination": target, "port": dest.port},
                    affected_resource=target,
                    source_provenance=provenance,
                    recommended_action="Verify service legitimacy on requested non-standard port.",
                )
            )

        # 4. Dangerous URI scheme
        if "://" in target:
            scheme = target.split("://")[0].lower()
            if scheme in SUSPICIOUS_SCHEMES:
                findings.append(
                    ThreatFinding(
                        request_id=request.request_id,
                        user_id=user_id,
                        agent_id=agent_id,
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                        threat_type=self.category,
                        title="Suspicious Network: Dangerous Protocol Scheme",
                        description=f"Request specifies high-risk protocol scheme '{scheme}://'.",
                        severity=ThreatSeverity.HIGH,
                        confidence=ThreatConfidence.HIGH,
                        risk_contribution=80.0,
                        evidence={"destination": target, "scheme": scheme},
                        affected_resource=target,
                        source_provenance=provenance,
                        recommended_action="Permit only verified HTTP/HTTPS protocol schemes.",
                    )
                )

        return findings
