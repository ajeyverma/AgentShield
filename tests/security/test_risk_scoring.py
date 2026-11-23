"""
AgentShield AI — Risk Scoring Engine Unit Tests (Phase 4).
"""

from __future__ import annotations

import uuid
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import IntegrationType, RiskLevel, ToolCategory
from agentshield.security.risk_scoring import RiskScoringEngine


def _req(tool="read_file", cat=ToolCategory.FILE_SYSTEM, op="read", res=None, perm=None):
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        integration_type=IntegrationType.SDK_OPENAI,
        tool_name=tool,
        tool_category=cat,
        operation=op,
        resource=res,
        requested_permissions=perm or [],
    )


class TestRiskScoringEngine:
    def test_low_risk_operation(self):
        req = _req(tool="read_doc", cat=ToolCategory.FILE_SYSTEM, op="read", res="/home/user/doc.txt")
        assessment = RiskScoringEngine.calculate_score(req)
        assert assessment.score < 25.0
        assert assessment.level == RiskLevel.LOW
        assert len(assessment.factors) >= 1

    def test_destructive_operation_increases_risk(self):
        req = _req(tool="file_remover", cat=ToolCategory.FILE_SYSTEM, op="delete", res="/tmp/test.tmp")
        assessment = RiskScoringEngine.calculate_score(req)
        assert assessment.score >= 50.0
        assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert any(f.factor_name == "DestructiveOperation" for f in assessment.factors)

    def test_sensitive_resource_increases_risk(self):
        req = _req(tool="read_file", cat=ToolCategory.FILE_SYSTEM, op="read", res="/app/.env")
        assessment = RiskScoringEngine.calculate_score(req)
        assert assessment.score >= 50.0
        assert any(f.factor_name == "SensitiveResourceTarget" for f in assessment.factors)

    def test_terminal_tool_high_base_risk(self):
        req = _req(tool="bash", cat=ToolCategory.TERMINAL, op="run", res="ls -la")
        assessment = RiskScoringEngine.calculate_score(req)
        assert assessment.score >= 40.0
        assert any(f.factor_name == "ToolSensitivity" for f in assessment.factors)

    def test_deterministic_scoring(self):
        req = _req(tool="sql_exec", cat=ToolCategory.DATABASE, op="write", res="users_table")
        score1 = RiskScoringEngine.calculate_score(req)
        score2 = RiskScoringEngine.calculate_score(req)
        assert score1.score == score2.score
        assert score1.level == score2.level
        assert len(score1.factors) == len(score2.factors)

    def test_score_boundaries_clamped_0_to_100(self):
        req = _req(
            tool="terminal_root",
            cat=ToolCategory.TERMINAL,
            op="delete",
            res="/etc/shadow/password.key",
            perm=["root", "admin", "execute", "write"],
        )
        assessment = RiskScoringEngine.calculate_score(req)
        assert assessment.score <= 100.0
        assert assessment.level == RiskLevel.CRITICAL
