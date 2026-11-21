"""
Unit tests for the SecurityDecision contract.

Covers:
  - Valid construction for each decision type.
  - Risk score bounds.
  - Approval fields populated only for ASK_HUMAN.
  - Serialization round-trip.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from agentshield.contracts.decision import PolicyMatch, SecurityDecision
from agentshield.contracts.enums import Decision, RiskLevel


REQUEST_ID = uuid.uuid4()


def _allow_decision(**overrides) -> dict:
    base = {
        "request_id": REQUEST_ID,
        "decision": Decision.ALLOW,
        "risk_score": 5.0,
        "risk_level": RiskLevel.LOW,
        "reasons": ["Action is within approved policy scope."],
    }
    base.update(overrides)
    return base


class TestSecurityDecisionConstruction:
    def test_allow_decision(self):
        d = SecurityDecision(**_allow_decision())
        assert d.decision == Decision.ALLOW
        assert d.risk_score == 5.0
        assert d.risk_level == RiskLevel.LOW
        assert not d.approval_required
        assert d.approval_id is None

    def test_block_decision(self):
        d = SecurityDecision(
            request_id=REQUEST_ID,
            decision=Decision.BLOCK,
            risk_score=95.0,
            risk_level=RiskLevel.CRITICAL,
            reasons=["Prohibited by policy P-001."],
            matched_policies=[
                PolicyMatch(
                    policy_id=uuid.uuid4(),
                    policy_name="Block sensitive file access",
                    rule_id="P-001-R-003",
                )
            ],
        )
        assert d.decision == Decision.BLOCK
        assert d.risk_level == RiskLevel.CRITICAL
        assert len(d.matched_policies) == 1
        assert d.matched_policies[0].rule_id == "P-001-R-003"

    def test_ask_human_decision(self):
        approval_id = uuid.uuid4()
        d = SecurityDecision(
            request_id=REQUEST_ID,
            decision=Decision.ASK_HUMAN,
            risk_score=60.0,
            risk_level=RiskLevel.HIGH,
            reasons=["Deletion outside sandbox requires approval."],
            approval_required=True,
            approval_id=approval_id,
            approval_timeout_seconds=300,
        )
        assert d.decision == Decision.ASK_HUMAN
        assert d.approval_required is True
        assert d.approval_id == approval_id
        assert d.approval_timeout_seconds == 300

    def test_decision_id_auto_generated(self):
        d = SecurityDecision(**_allow_decision())
        assert isinstance(d.decision_id, uuid.UUID)

    def test_evaluated_at_auto_populated(self):
        d = SecurityDecision(**_allow_decision())
        assert d.evaluated_at is not None


class TestSecurityDecisionValidation:
    def test_risk_score_minimum(self):
        with pytest.raises(ValidationError):
            SecurityDecision(**_allow_decision(risk_score=-1.0))

    def test_risk_score_maximum(self):
        with pytest.raises(ValidationError):
            SecurityDecision(**_allow_decision(risk_score=100.1))

    def test_risk_score_zero_allowed(self):
        d = SecurityDecision(**_allow_decision(risk_score=0.0))
        assert d.risk_score == 0.0

    def test_risk_score_100_allowed(self):
        d = SecurityDecision(**_allow_decision(risk_score=100.0))
        assert d.risk_score == 100.0

    def test_invalid_decision_raises(self):
        with pytest.raises(ValidationError):
            SecurityDecision(**_allow_decision(decision="PERMIT"))

    def test_invalid_risk_level_raises(self):
        with pytest.raises(ValidationError):
            SecurityDecision(**_allow_decision(risk_level="EXTREME"))

    def test_approval_timeout_minimum(self):
        with pytest.raises(ValidationError):
            SecurityDecision(**_allow_decision(approval_timeout_seconds=0))

    def test_missing_request_id_raises(self):
        data = _allow_decision()
        data.pop("request_id")
        with pytest.raises(ValidationError):
            SecurityDecision(**data)


class TestSecurityDecisionSerialization:
    def test_json_round_trip(self):
        d = SecurityDecision(**_allow_decision())
        json_str = d.model_dump_json()
        restored = SecurityDecision.model_validate_json(json_str)
        assert restored.decision == d.decision
        assert restored.risk_score == d.risk_score
        assert restored.request_id == d.request_id
        assert restored.decision_id == d.decision_id
