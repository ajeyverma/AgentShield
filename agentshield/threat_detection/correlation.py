"""
AgentShield AI — Threat Correlation Engine (Phase 5).

Combines related threat signals across findings, requests, and historical sessions
into synthesized attack chains with explainable risk contributions.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Sequence

from agentshield.contracts.threat import (
    CorrelatedThreat,
    ThreatCategory,
    ThreatFinding,
    ThreatSeverity,
)
from agentshield.threat_detection.severity import SEVERITY_WEIGHTS, score_to_severity


class ThreatCorrelationEngine:
    """Deterministic correlation engine for synthesizing multi-stage threat findings."""

    @classmethod
    def correlate(
        cls,
        agent_id: str,
        findings: Sequence[ThreatFinding],
        session_id: str | None = None,
    ) -> tuple[list[CorrelatedThreat], float, ThreatSeverity]:
        """Correlate findings and return (correlations, overall_threat_score, highest_severity)."""
        if not findings:
            return [], 0.0, ThreatSeverity.LOW

        correlations: list[CorrelatedThreat] = []
        finding_types = {f.threat_type for f in findings}
        finding_ids = [str(f.finding_id) for f in findings]

        # ── Multi-Stage Pattern 1: Prompt Injection + Credential Access ─────
        if ThreatCategory.PROMPT_INJECTION in finding_types and ThreatCategory.DATA_LEAKAGE in finding_types:
            correlations.append(
                CorrelatedThreat(
                    correlation_id=uuid.uuid4(),
                    agent_id=agent_id,
                    session_id=session_id,
                    threat_score=95.0,
                    overall_severity=ThreatSeverity.CRITICAL,
                    title="Exfiltration Chain: Prompt Injection with Credential Harvest",
                    explanation="Agent received prompt injection instructions combined with cleartext credential exposure.",
                    correlated_finding_ids=finding_ids,
                    recommended_response="Isolate agent session, revoke exposed credentials, and block tool execution.",
                )
            )

        # ── Multi-Stage Pattern 2: Prompt Injection + Dangerous Command ─────
        if ThreatCategory.PROMPT_INJECTION in finding_types and ThreatCategory.DANGEROUS_COMMAND in finding_types:
            correlations.append(
                CorrelatedThreat(
                    correlation_id=uuid.uuid4(),
                    agent_id=agent_id,
                    session_id=session_id,
                    threat_score=100.0,
                    overall_severity=ThreatSeverity.CRITICAL,
                    title="Attack Chain: Prompt Injection Driving Dangerous Command Execution",
                    explanation="Untrusted prompt injection directly precedes catastrophic or high-risk shell command request.",
                    correlated_finding_ids=finding_ids,
                    recommended_response="Immediately terminate agent execution and alert security operations.",
                )
            )

        # ── Multi-Stage Pattern 3: Filesystem Traversal + Network Egress ──────
        if ThreatCategory.FILESYSTEM in finding_types and ThreatCategory.SUSPICIOUS_NETWORK in finding_types:
            correlations.append(
                CorrelatedThreat(
                    correlation_id=uuid.uuid4(),
                    agent_id=agent_id,
                    session_id=session_id,
                    threat_score=90.0,
                    overall_severity=ThreatSeverity.CRITICAL,
                    title="Exfiltration Chain: Filesystem Traversal Followed by Network Egress",
                    explanation="Suspicious directory traversal accompanied by outbound network transmission attempt.",
                    correlated_finding_ids=finding_ids,
                    recommended_response="Block external network egress and verify integrity of accessed files.",
                )
            )

        # ── Composite Threat Score Calculation ──────────────────────────────
        # Base on highest individual risk contribution plus diminishing returns for additional findings
        sorted_scores = sorted((f.risk_contribution for f in findings), reverse=True)
        combined_score = sorted_scores[0]
        for sc in sorted_scores[1:]:
            combined_score += (100.0 - combined_score) * (sc / 250.0)

        # If any correlation triggered, boost score to reflect compounded risk
        if correlations:
            max_corr = max(c.threat_score for c in correlations)
            combined_score = max(combined_score, max_corr)

        final_score = round(min(100.0, max(0.0, combined_score)), 1)
        highest_sev = score_to_severity(final_score)

        return correlations, final_score, highest_sev
