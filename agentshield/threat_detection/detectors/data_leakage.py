"""
AgentShield AI — Sensitive Data & Leakage Detector (Phase 5).

Detects API keys, tokens, credentials, private keys, and PII in tool arguments,
resources, and outbound payloads.
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
from agentshield.threat_detection.analyzers.content_analyzer import ContentAnalyzer
from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.rules.sensitive_data_rules import (
    SENSITIVE_FIELD_NAMES,
    SENSITIVE_FILE_NAMES,
)


class DataLeakageDetector(BaseDetector):
    """Detector for credentials, confidential data leakage, and secret exposure."""

    detector_id = "DET-DATA-002"
    detector_name = "Sensitive Data Exposure & Leakage Detector"
    detector_version = "1.0.0"
    category = ThreatCategory.DATA_LEAKAGE

    def analyze(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        user_id = str(request.user_id or "unknown")
        agent_id = str(request.agent_id)

        # 1. Inspect arguments for raw secrets and redact them
        redacted_args, detected_secrets = ContentAnalyzer.redact_data(request.arguments)

        if detected_secrets:
            # Check if this is an outbound transmission tool
            is_egress = request.tool_category in (ToolCategory.NETWORK, ToolCategory.EXTERNAL_API, ToolCategory.EMAIL) or any(
                eg in request.tool_name.lower() for eg in ("http", "curl", "post", "send", "mail", "api")
            )
            severity = ThreatSeverity.CRITICAL if is_egress else ThreatSeverity.HIGH
            risk = 90.0 if is_egress else 70.0

            findings.append(
                ThreatFinding(
                    request_id=request.request_id,
                    user_id=user_id,
                    agent_id=agent_id,
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    threat_type=self.category,
                    title="Sensitive Data Exposure: Cleartext Credentials Detected",
                    description=f"Action arguments contain sensitive secret patterns: {', '.join(detected_secrets)}.",
                    severity=severity,
                    confidence=ThreatConfidence.HIGH,
                    risk_contribution=risk,
                    evidence={
                        "detected_secret_types": detected_secrets,
                        "is_outbound_egress": is_egress,
                        "redacted_arguments_keys": list(redacted_args.keys()) if isinstance(redacted_args, dict) else [],
                    },
                    affected_resource=request.resource,
                    source_provenance=provenance,
                    recommended_action="Redact secret values, rotate exposed credentials, and inspect caller intention.",
                )
            )

        # 2. Inspect target resource for known credential file names
        target_resource = ActionAnalyzer.extract_target_resource(request)
        if target_resource:
            for pat in SENSITIVE_FILE_NAMES:
                if pat.search(target_resource):
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Sensitive Resource Access: Credential Store Targeted",
                            description=f"Target resource points to high-sensitivity credential file: '{target_resource}'.",
                            severity=ThreatSeverity.HIGH,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=80.0,
                            evidence={"target_resource": target_resource, "pattern": pat.pattern},
                            affected_resource=target_resource,
                            source_provenance=provenance,
                            recommended_action="Restrict agent access to secret configurations and keyfiles.",
                        )
                    )
                    break

        return findings
