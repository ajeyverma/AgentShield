"""
AgentShield AI — Threat Detection API Schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.provenance import ProvenanceContext
from agentshield.contracts.threat import (
    CorrelatedThreat,
    FindingStatus,
    ThreatAnalysisResult,
    ThreatCategory,
    ThreatConfidence,
    ThreatFinding,
    ThreatSeverity,
)


class ThreatAnalyzeRequest(BaseModel):
    """Request payload for standalone threat analysis."""

    action_request: ActionRequest
    provenance: ProvenanceContext | None = None
    relevant_history: list[dict[str, Any]] = Field(default_factory=list)


class ThreatFindingResponse(BaseModel):
    """API response model for a single threat finding."""

    id: str
    request_id: str
    user_id: str
    agent_id: str
    detector_id: str
    threat_type: str
    title: str
    description: str
    severity: str
    confidence: str
    risk_contribution: float
    evidence: dict[str, Any]
    affected_resource: str | None
    recommended_action: str
    status: str
    detector_version: str
    created_at: datetime


class ThreatFindingUpdate(BaseModel):
    """Payload to update finding status."""

    status: FindingStatus


class ThreatSummaryResponse(BaseModel):
    """High-level threat detection metrics summary."""

    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    category_distribution: dict[str, int]
    recent_findings: list[ThreatFindingResponse]


class DetectorMetadata(BaseModel):
    """Registered detector information."""

    detector_id: str
    detector_name: str
    category: str
    version: str
    is_active: bool
    description: str
