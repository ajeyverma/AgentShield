"""
AgentShield AI — Prompt Injection Detector (Phase 5).

Analyzes text arguments, inputs, and provenance context for instruction overrides,
jailbreaks, system prompt disclosure, and delimiter evasion.
"""

from __future__ import annotations

from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.provenance import ProvenanceContext, TrustLevel
from agentshield.contracts.threat import (
    ThreatCategory,
    ThreatConfidence,
    ThreatFinding,
    ThreatSeverity,
)
from agentshield.threat_detection.analyzers.action_analyzer import ActionAnalyzer
from agentshield.threat_detection.analyzers.content_analyzer import ContentAnalyzer
from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.rules.prompt_injection_rules import (
    DISCLOSURE_PATTERNS,
    EXFILTRATION_INSTRUCTION_PATTERNS,
    INJECTION_OVERRIDE_PATTERNS,
    ROLE_FORGERY_PATTERNS,
)


class PromptInjectionDetector(BaseDetector):
    """Detector for direct, indirect, and obfuscated prompt injection attempts."""

    detector_id = "DET-PI-001"
    detector_name = "Prompt Injection & Jailbreak Detector"
    detector_version = "1.0.0"
    category = ThreatCategory.PROMPT_INJECTION

    def analyze(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        user_id = str(request.user_id or "unknown")
        agent_id = str(request.agent_id)

        # 1. Gather all candidate text payloads
        candidate_strings = ActionAnalyzer.extract_string_payloads(request.arguments)
        if request.resource:
            candidate_strings.append(request.resource)
        if provenance and provenance.raw_content_preview:
            candidate_strings.append(provenance.raw_content_preview)

        # Provenance trust check
        is_untrusted_source = False
        if provenance:
            is_untrusted_source = provenance.is_untrusted

        for text in candidate_strings:
            if not text or len(text.strip()) < 5:
                continue

            # A. Instruction Overrides & Jailbreaks
            for pat in INJECTION_OVERRIDE_PATTERNS:
                match = pat.search(text)
                if match:
                    # Check false-positive context: if trusted user asks about prompt injection
                    is_discussion = "how to" in text.lower() or "example of" in text.lower() or "detect" in text.lower()
                    if is_discussion and not is_untrusted_source:
                        severity = ThreatSeverity.LOW
                        confidence = ThreatConfidence.LOW
                    elif is_untrusted_source:
                        severity = ThreatSeverity.CRITICAL
                        confidence = ThreatConfidence.HIGH
                    else:
                        severity = ThreatSeverity.HIGH
                        confidence = ThreatConfidence.MEDIUM

                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Prompt Injection: Instruction Override Detected",
                            description=f"Suspicious directive attempting to override agent instructions: '{match.group(0)}'.",
                            severity=severity,
                            confidence=confidence,
                            risk_contribution=85.0 if severity == ThreatSeverity.CRITICAL else 65.0,
                            evidence={
                                "matched_pattern": match.group(0),
                                "snippet": text[:120],
                                "untrusted_source": is_untrusted_source,
                            },
                            affected_resource=request.resource,
                            source_provenance=provenance,
                            recommended_action="Quarantine input and review source provenance for prompt injection.",
                        )
                    )
                    break

            # B. System Prompt Disclosure
            for pat in DISCLOSURE_PATTERNS:
                match = pat.search(text)
                if match:
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Prompt Injection: System Prompt Disclosure Attempt",
                            description=f"Request attempts to extract internal system prompt or credentials: '{match.group(0)}'.",
                            severity=ThreatSeverity.HIGH,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=75.0,
                            evidence={"matched_pattern": match.group(0), "snippet": text[:120]},
                            affected_resource=request.resource,
                            source_provenance=provenance,
                            recommended_action="Block prompt extraction and sanitize agent prompt context.",
                        )
                    )
                    break

            # C. Role Forgery / Delimiter Evasion
            for pat in ROLE_FORGERY_PATTERNS:
                match = pat.search(text)
                if match:
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Prompt Injection: Role Delimiter Forgery",
                            description=f"Synthesized system or role delimiter detected: '{match.group(0)}'.",
                            severity=ThreatSeverity.MEDIUM if not is_untrusted_source else ThreatSeverity.HIGH,
                            confidence=ThreatConfidence.MEDIUM,
                            risk_contribution=50.0,
                            evidence={"matched_pattern": match.group(0), "snippet": text[:120]},
                            affected_resource=request.resource,
                            source_provenance=provenance,
                            recommended_action="Strip synthetic role markers and inspect input boundaries.",
                        )
                    )
                    break

            # D. Exfiltration Instructions
            for pat in EXFILTRATION_INSTRUCTION_PATTERNS:
                match = pat.search(text)
                if match:
                    findings.append(
                        ThreatFinding(
                            request_id=request.request_id,
                            user_id=user_id,
                            agent_id=agent_id,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            threat_type=self.category,
                            title="Prompt Injection: Embedded Data Exfiltration Directive",
                            description="Content contains directives instructing agent to exfiltrate data externally.",
                            severity=ThreatSeverity.CRITICAL,
                            confidence=ThreatConfidence.HIGH,
                            risk_contribution=90.0,
                            evidence={"matched_pattern": match.group(0), "snippet": text[:120]},
                            affected_resource=request.resource,
                            source_provenance=provenance,
                            recommended_action="Isolate agent session and block external egress.",
                        )
                    )
                    break

            # E. Obfuscation Signals (Base64 / Hex Encoded Instructions)
            obf = ContentAnalyzer.inspect_obfuscation(text)
            for item in obf:
                findings.append(
                    ThreatFinding(
                        request_id=request.request_id,
                        user_id=user_id,
                        agent_id=agent_id,
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                        threat_type=self.category,
                        title="Prompt Injection: Obfuscated Command Payload",
                        description=item,
                        severity=ThreatSeverity.HIGH,
                        confidence=ThreatConfidence.MEDIUM,
                        risk_contribution=70.0,
                        evidence={"explanation": item},
                        affected_resource=request.resource,
                        source_provenance=provenance,
                        recommended_action="Inspect decoded payload before allowing execution.",
                    )
                )

        return findings
