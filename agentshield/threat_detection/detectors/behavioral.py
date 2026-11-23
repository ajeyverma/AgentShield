"""
AgentShield AI — Behavioral Anomaly Detector (Phase 5).

Analyzes historical request frequency, denial rates, and high-risk action sequences
per agent with strict user/tenant isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.provenance import ProvenanceContext
from agentshield.contracts.threat import (
    ThreatCategory,
    ThreatConfidence,
    ThreatFinding,
    ThreatSeverity,
)
from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.rules.behavioral_rules import (
    EXFILTRATION_TOOL_SEQUENCE,
    MAX_CONSECUTIVE_DENIALS,
    MAX_REQUESTS_PER_MINUTE,
)


class BehavioralAnomalyDetector(BaseDetector):
    """Statistical and heuristic anomaly detector over agent activity history."""

    detector_id = "DET-BEH-006"
    detector_name = "Agent Behavioral Anomaly Detector"
    detector_version = "1.0.0"
    category = ThreatCategory.BEHAVIORAL_ANOMALY

    def analyze(
        self,
        request: ActionRequest,
        provenance: ProvenanceContext | None = None,
        history: list[dict[str, Any]] | None = None,
    ) -> list[ThreatFinding]:
        findings: list[ThreatFinding] = []
        user_id = str(request.user_id or "unknown")
        agent_id = str(request.agent_id)

        if not history:
            # Baseline absent: for new agents, don't generate false positives
            return findings

        # Filter history strictly to this agent and user (tenant isolation)
        agent_history = [
            h for h in history
            if str(h.get("agent_id")) == agent_id and (not h.get("user_id") or str(h.get("user_id")) == user_id)
        ]

        if not agent_history:
            return findings

        now = datetime.now(UTC)
        one_min_ago = now - timedelta(minutes=1)

        # 1. Burst Frequency Check (>30 req/min)
        recent_count = sum(
            1 for h in agent_history
            if h.get("created_at") and isinstance(h.get("created_at"), datetime) and h["created_at"] >= one_min_ago
        )
        if recent_count >= MAX_REQUESTS_PER_MINUTE:
            findings.append(
                ThreatFinding(
                    request_id=request.request_id,
                    user_id=user_id,
                    agent_id=agent_id,
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    threat_type=self.category,
                    title="Behavioral Anomaly: Request Rate Spike Detected",
                    description=f"Agent generated {recent_count} requests in 60s window (threshold: {MAX_REQUESTS_PER_MINUTE}).",
                    severity=ThreatSeverity.MEDIUM,
                    confidence=ThreatConfidence.HIGH,
                    risk_contribution=50.0,
                    evidence={"requests_last_minute": recent_count, "threshold": MAX_REQUESTS_PER_MINUTE},
                    affected_resource="rate_limit",
                    source_provenance=provenance,
                    recommended_action="Throttle agent request rate and investigate potential automation loop.",
                )
            )

        # 2. Repeated Consecutive Denials Check (>=3)
        consecutive_denials = 0
        for h in reversed(agent_history):
            decision = str(h.get("decision", "")).upper()
            if decision in ("BLOCK", "DENIED"):
                consecutive_denials += 1
            else:
                break

        if consecutive_denials >= MAX_CONSECUTIVE_DENIALS:
            findings.append(
                ThreatFinding(
                    request_id=request.request_id,
                    user_id=user_id,
                    agent_id=agent_id,
                    detector_id=self.detector_id,
                    detector_version=self.detector_version,
                    threat_type=self.category,
                    title="Behavioral Anomaly: Repeated Security Authorization Denials",
                    description=f"Agent encountered {consecutive_denials} consecutive authorization blocks.",
                    severity=ThreatSeverity.HIGH,
                    confidence=ThreatConfidence.HIGH,
                    risk_contribution=75.0,
                    evidence={"consecutive_denials": consecutive_denials, "threshold": MAX_CONSECUTIVE_DENIALS},
                    affected_resource="security_boundary",
                    source_provenance=provenance,
                    recommended_action="Pause agent operations and review policy compliance.",
                )
            )

        # 3. Suspicious Multi-Action Sequence: File Read immediately followed by Outbound Network
        if len(agent_history) >= 1:
            last_event = agent_history[-1]
            last_tool = str(last_event.get("tool_name", "")).lower()
            current_tool = request.tool_name.lower()

            if any(r in last_tool for r in ("read", "file", "fs")) and any(n in current_tool for n in ("http", "post", "send", "curl", "net")):
                findings.append(
                    ThreatFinding(
                        request_id=request.request_id,
                        user_id=user_id,
                        agent_id=agent_id,
                        detector_id=self.detector_id,
                        detector_version=self.detector_version,
                        threat_type=self.category,
                        title="Behavioral Anomaly: High-Risk Action Sequence (Read -> Network Egress)",
                        description=f"Agent performed file read ('{last_tool}') immediately followed by outbound egress ('{current_tool}').",
                        severity=ThreatSeverity.HIGH,
                        confidence=ThreatConfidence.MEDIUM,
                        risk_contribution=70.0,
                        evidence={"previous_action": last_tool, "current_action": current_tool},
                        affected_resource=request.resource,
                        source_provenance=provenance,
                        recommended_action="Inspect payload data for possible exfiltration of previously read file contents.",
                    )
                )

        return findings
