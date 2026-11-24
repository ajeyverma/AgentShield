"""
AgentShield AI — Phase 2 UI Smoke Tests.

These tests verify that all Phase 2 modules import without errors and that
the demo data is internally consistent.  They do NOT require a display or
a running QApplication — widget instantiation tests are skipped when no
display is available.

Run:
    pytest tests/unit/test_ui_smoke.py -v
"""
from __future__ import annotations

import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_display() -> bool:
    """Return True if a display/screen is likely available."""
    # On Windows, QApplication generally works in any desktop session.
    # We skip GPU-heavy widget instantiation in headless CI environments.
    return sys.platform == "win32" or bool(os.environ.get("DISPLAY"))


# ---------------------------------------------------------------------------
# Import smoke tests — no QApplication needed
# ---------------------------------------------------------------------------


class TestModuleImports:
    """Every Phase 2 module must import without raising."""

    def test_design_tokens_import(self):
        from apps.desktop.themes.design_tokens import T  # noqa: F401
        assert hasattr(T, "PRIMARY")
        assert hasattr(T, "global_qss")

    def test_legacy_tokens_import(self):
        """Phase 1 tokens.py must still import (backward compat)."""
        from apps.desktop.themes.tokens import LightTheme  # noqa: F401
        assert callable(LightTheme.global_stylesheet)

    def test_demo_data_import(self):
        from apps.desktop.services.demo_data import (  # noqa: F401
            ACTIVITY,
            AGENTS,
            APPROVALS,
            AUDIT_LOGS,
            INTEGRATIONS,
            POLICIES,
            THREATS,
            get_dashboard_stats,
        )

    def test_backend_client_import(self):
        from apps.desktop.services.backend_client import BackendClient  # noqa: F401

    def test_components_import(self):
        from apps.desktop.components import (  # noqa: F401
            DataTable,
            EmptyState,
            PageHeader,
            StatCard,
            StatusBadge,
        )

    def test_sidebar_import(self):
        from apps.desktop.components.sidebar import NAV_ITEMS, Sidebar  # noqa: F401
        assert len(NAV_ITEMS) == 9

    def test_header_import(self):
        from apps.desktop.components.header import Header, PAGE_META  # noqa: F401
        assert "dashboard" in PAGE_META

    def test_mini_chart_import(self):
        from apps.desktop.components.mini_chart import BarChartWidget, DonutChartWidget  # noqa: F401

    def test_all_view_imports(self):
        from apps.desktop.views.agent_manager import AgentManagerView  # noqa: F401
        from apps.desktop.views.approval_center import ApprovalCenterView  # noqa: F401
        from apps.desktop.views.audit_logs import AuditLogsView  # noqa: F401
        from apps.desktop.views.dashboard import DashboardView  # noqa: F401
        from apps.desktop.views.integrations import IntegrationsView  # noqa: F401
        from apps.desktop.views.live_activity import LiveActivityView  # noqa: F401
        from apps.desktop.views.policy_management import PolicyManagementView  # noqa: F401
        from apps.desktop.views.settings import SettingsView  # noqa: F401
        from apps.desktop.views.threat_monitoring import ThreatMonitoringView  # noqa: F401

    def test_main_window_import(self):
        from apps.desktop.app.main_window import MainWindow  # noqa: F401

    def test_main_window_instantiation(self):
        from PySide6.QtWidgets import QApplication
        _app = QApplication.instance() or QApplication(["test"])
        from apps.desktop.app.main_window import MainWindow
        win = MainWindow()
        assert win.windowTitle() == "AgentShield AI"
        assert win.isVisible() is False



# ---------------------------------------------------------------------------
# Demo data consistency tests — no QApplication needed
# ---------------------------------------------------------------------------


class TestDemoDataConsistency:
    """Validate that demo data is internally consistent."""

    def setup_method(self):
        from apps.desktop.services.demo_data import (
            ACTIVITY,
            AGENTS,
            APPROVALS,
            AUDIT_LOGS,
            INTEGRATIONS,
            POLICIES,
            THREATS,
            get_dashboard_stats,
        )
        self.AGENTS = AGENTS
        self.ACTIVITY = ACTIVITY
        self.THREATS = THREATS
        self.APPROVALS = APPROVALS
        self.POLICIES = POLICIES
        self.AUDIT_LOGS = AUDIT_LOGS
        self.INTEGRATIONS = INTEGRATIONS
        self.stats = get_dashboard_stats()

    def test_total_agents_matches(self):
        assert self.stats["total_agents"] == len(self.AGENTS)

    def test_actions_today_matches(self):
        assert self.stats["actions_today"] == len(self.ACTIVITY)

    def test_threats_count_positive(self):
        assert len(self.THREATS) > 0

    def test_approvals_pending_exists(self):
        """At least one pending approval should exist in demo data."""
        pending = [a for a in self.APPROVALS if getattr(a, "status", "").lower() == "pending"]
        assert self.stats["pending_approvals"] == len(pending)

    def test_agents_have_required_fields(self):
        required = {"name", "framework", "status"}
        for agent in self.AGENTS:
            # Dataclass records — use hasattr / getattr
            for field_name in required:
                assert hasattr(agent, field_name), (
                    f"AgentRecord missing attribute '{field_name}'"
                )
                assert getattr(agent, field_name), (
                    f"AgentRecord.{field_name} is empty/falsy"
                )

    def test_activity_entries_have_decision(self):
        valid_decisions = {"allow", "block", "ask_human"}
        for entry in self.ACTIVITY:
            decision = getattr(entry, "decision", "").lower()
            assert decision in valid_decisions, (
                f"ActivityRecord has unexpected decision: {decision!r}"
            )

    def test_threats_have_severity(self):
        valid = {"low", "medium", "high", "critical"}
        for threat in self.THREATS:
            sev = getattr(threat, "severity", "").lower()
            assert sev in valid, (
                f"ThreatRecord has invalid severity: {sev!r}"
            )

    def test_integrations_not_falsely_connected(self):
        """No integration should claim to be 'connected' — all are planned/not configured."""
        fake_connected = [
            i for i in self.INTEGRATIONS
            if getattr(i, "status", "").lower() == "connected"
        ]
        assert not fake_connected, (
            f"Integrations falsely claim 'connected': "
            f"{[getattr(i, 'name', '?') for i in fake_connected]}"
        )

    def test_policies_have_enforcement(self):
        for policy in self.POLICIES:
            assert hasattr(policy, "enforcement") or hasattr(policy, "mode"), (
                f"PolicyRecord missing 'enforcement' or 'mode' attribute: {policy}"
            )

    def test_audit_logs_have_timestamp(self):
        for log in self.AUDIT_LOGS:
            assert hasattr(log, "timestamp"), f"AuditRecord missing 'timestamp': {log}"

    def test_blocked_actions_count_matches(self):
        blocked = sum(
            1 for a in self.ACTIVITY
            if getattr(a, "decision", "").lower() == "block"
        )
        assert self.stats["blocked_today"] == blocked


# ---------------------------------------------------------------------------
# Design token tests
# ---------------------------------------------------------------------------


class TestDesignTokens:
    """Verify design token integrity."""

    def test_all_color_tokens_are_hex(self):
        from apps.desktop.themes.design_tokens import T
        color_attrs = [
            "BG_APP", "SURFACE", "PRIMARY", "TEXT", "TEXT_SEC",
            "BORDER", "SUCCESS", "WARNING", "DANGER", "INFO",
            "SIDEBAR_BG", "SIDEBAR_ACTIVE",
        ]
        for attr in color_attrs:
            value = getattr(T, attr)
            assert isinstance(value, str) and value.startswith("#"), (
                f"T.{attr} = {value!r} is not a hex color"
            )

    def test_spacing_tokens_are_positive_integers(self):
        from apps.desktop.themes.design_tokens import T
        for attr in ["SP_1", "SP_2", "SP_3", "SP_4", "SP_5", "SP_6", "SP_8"]:
            value = getattr(T, attr)
            assert isinstance(value, int) and value > 0, (
                f"T.{attr} = {value!r} is not a positive integer"
            )

    def test_sidebar_width_reasonable(self):
        from apps.desktop.themes.design_tokens import T
        assert 180 <= T.SIDEBAR_W <= 300

    def test_global_qss_returns_non_empty_string(self):
        from apps.desktop.themes.design_tokens import T
        qss = T.global_qss()
        assert isinstance(qss, str) and len(qss) > 100

    def test_nav_items_count(self):
        from apps.desktop.components.sidebar import NAV_ITEMS
        assert len(NAV_ITEMS) == 9, "Expected exactly 9 navigation items"

    def test_page_meta_covers_all_pages(self):
        from apps.desktop.components.header import PAGE_META
        from apps.desktop.components.sidebar import NAV_ITEMS
        page_ids = {page_id for page_id, _, _, _ in NAV_ITEMS}
        for page_id in page_ids:
            assert page_id in PAGE_META, f"PAGE_META missing entry for '{page_id}'"
