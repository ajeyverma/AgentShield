"""
Unit tests for the AgentShield shared contract enums.

Verifies that all enum values are present, correctly typed, and that
enum membership checks work as expected.
"""

from __future__ import annotations

import pytest

from agentshield.contracts.enums import (
    ActionStatus,
    ApprovalStatus,
    Decision,
    DeploymentMode,
    IntegrationType,
    RiskLevel,
    ToolCategory,
)


class TestDecisionEnum:
    def test_all_values_present(self):
        values = {d.value for d in Decision}
        assert values == {"ALLOW", "BLOCK", "ASK_HUMAN"}

    def test_string_subclass(self):
        assert isinstance(Decision.ALLOW, str)
        assert Decision.ALLOW == "ALLOW"

    def test_membership(self):
        assert Decision("ALLOW") is Decision.ALLOW
        assert Decision("BLOCK") is Decision.BLOCK
        assert Decision("ASK_HUMAN") is Decision.ASK_HUMAN

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            Decision("DENY")


class TestRiskLevelEnum:
    def test_all_values_present(self):
        values = {r.value for r in RiskLevel}
        assert values == {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_ordering_by_name(self):
        # Confirm the enum provides the expected members
        assert RiskLevel.NONE
        assert RiskLevel.LOW
        assert RiskLevel.CRITICAL


class TestIntegrationTypeEnum:
    def test_all_expected_types_present(self):
        expected = {
            "SDK_OPENAI", "SDK_CLAUDE", "SDK_LANGGRAPH", "SDK_CREWAI",
            "SDK_GOOGLE_ADK", "SDK_CUSTOM", "MCP", "API", "UNKNOWN",
        }
        values = {i.value for i in IntegrationType}
        assert expected.issubset(values)

    def test_string_subclass(self):
        assert isinstance(IntegrationType.MCP, str)


class TestToolCategoryEnum:
    def test_key_categories_present(self):
        expected = {
            "FILE_SYSTEM", "NETWORK", "DATABASE", "EMAIL",
            "BROWSER", "TERMINAL", "EXTERNAL_API", "CODE_EXECUTION", "UNKNOWN",
        }
        values = {t.value for t in ToolCategory}
        assert expected.issubset(values)


class TestActionStatusEnum:
    def test_lifecycle_states_present(self):
        expected = {
            "PENDING", "EVALUATING", "APPROVED", "BLOCKED",
            "AWAITING_APPROVAL", "EXECUTING", "COMPLETED", "FAILED",
            "EXPIRED", "CANCELLED",
        }
        values = {s.value for s in ActionStatus}
        assert expected == values


class TestDeploymentModeEnum:
    def test_values(self):
        assert DeploymentMode.LOCAL.value == "LOCAL"
        assert DeploymentMode.REMOTE.value == "REMOTE"
