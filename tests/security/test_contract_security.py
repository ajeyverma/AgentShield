"""
Security contract tests.

Validates security-critical properties of the shared contracts:
  - Identity fields cannot be set from agent-supplied strings via JSON.
  - Oversized payloads are rejected.
  - Decision values are strictly typed (no forging).
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import SecurityDecision
from agentshield.contracts.enums import Decision, IntegrationType, RiskLevel


class TestActionRequestSecurityProperties:
    """Security properties that must hold for every ActionRequest."""

    def test_tenant_id_must_be_uuid_not_arbitrary_string(self):
        """Reject non-UUID tenant_id values to prevent injection from agent payloads."""
        with pytest.raises(ValidationError):
            ActionRequest(
                tenant_id="admin",  # type: ignore[arg-type]
                agent_id=uuid.uuid4(),
                integration_type=IntegrationType.API,
                tool_name="list_files",
            )

    def test_agent_id_must_be_uuid(self):
        with pytest.raises(ValidationError):
            ActionRequest(
                tenant_id=uuid.uuid4(),
                agent_id="../../../etc/passwd",  # type: ignore[arg-type]
                integration_type=IntegrationType.API,
                tool_name="list_files",
            )

    def test_arguments_must_be_json_serializable(self):
        """Non-serializable arguments should be rejected."""
        with pytest.raises(ValidationError):
            ActionRequest(
                tenant_id=uuid.uuid4(),
                agent_id=uuid.uuid4(),
                integration_type=IntegrationType.API,
                tool_name="execute",
                arguments={"fn": lambda x: x},  # type: ignore[arg-type]
            )

    def test_oversized_arguments_blocked(self):
        """Confirm the 65 536-byte arguments limit is enforced."""
        with pytest.raises(ValidationError, match="arguments payload exceeds"):
            ActionRequest(
                tenant_id=uuid.uuid4(),
                agent_id=uuid.uuid4(),
                integration_type=IntegrationType.API,
                tool_name="execute",
                arguments={"payload": "A" * 70_000},
            )


class TestSecurityDecisionIntegrity:
    """Verify that decision values cannot be forged or corrupted."""

    def test_decision_enum_strict_values(self):
        """Only the three canonical decision values are accepted."""
        for valid in ("ALLOW", "BLOCK", "ASK_HUMAN"):
            d = SecurityDecision(
                request_id=uuid.uuid4(),
                decision=valid,  # type: ignore[arg-type]
                risk_score=0.0,
                risk_level=RiskLevel.NONE,
            )
            assert d.decision in Decision

        for invalid in ("PERMIT", "DENY", "YES", "allow", "1"):
            with pytest.raises(ValidationError):
                SecurityDecision(
                    request_id=uuid.uuid4(),
                    decision=invalid,  # type: ignore[arg-type]
                    risk_score=0.0,
                    risk_level=RiskLevel.NONE,
                )

    def test_risk_score_bounds_enforced(self):
        with pytest.raises(ValidationError):
            SecurityDecision(
                request_id=uuid.uuid4(),
                decision=Decision.ALLOW,
                risk_score=-0.1,
                risk_level=RiskLevel.NONE,
            )
        with pytest.raises(ValidationError):
            SecurityDecision(
                request_id=uuid.uuid4(),
                decision=Decision.ALLOW,
                risk_score=100.1,
                risk_level=RiskLevel.NONE,
            )
