"""
AgentShield AI — Desktop Application Main Window (Phase 2).

Integrates sidebar navigation, header bar, and a QStackedWidget containing
all nine content views.  The sidebar's page_changed signal drives both the
stack index and the header state.

Architecture
------------
  QMainWindow
    centralWidget (QWidget, QHBoxLayout, no margins)
      Sidebar  (fixed 220 px, dark)
      right_panel (QWidget, QVBoxLayout, no margins)
        Header   (fixed 56 px, light)
        QStackedWidget  (remaining height)
          0  DashboardView
          1  AgentManagerView
          2  LiveActivityView
          3  ThreatMonitoringView
          4  ApprovalCenterView
          5  PolicyManagementView
          6  AuditLogsView
          7  IntegrationsView
          8  SettingsView
    QStatusBar  (bottom)

Nothing in this file performs real security evaluation.  All data shown
by the views is explicitly labelled as demonstration data.
"""
from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.components.header import Header
from apps.desktop.components.sidebar import NAV_ITEMS, Sidebar
from apps.desktop.themes.design_tokens import T
from apps.desktop.views.agent_manager import AgentManagerView
from apps.desktop.views.approval_center import ApprovalCenterView
from apps.desktop.views.audit_logs import AuditLogsView
from apps.desktop.views.dashboard import DashboardView
from apps.desktop.views.integrations import IntegrationsView
from apps.desktop.views.live_activity import LiveActivityView
from apps.desktop.views.policy_management import PolicyManagementView
from apps.desktop.views.settings import SettingsView
from apps.desktop.views.threat_monitoring import ThreatMonitoringView

logger = logging.getLogger("agentshield.desktop.main_window")

# Page order must match NAV_ITEMS order exactly
_PAGE_ORDER = [page_id for page_id, _, _, _ in NAV_ITEMS]
# dashboard, agents, activity, threats, approvals, policies, audit, integrations, settings

_APP_VERSION = "0.2.0"


class MainWindow(QMainWindow):
    """AgentShield AI main application window (Phase 2 — full UI shell)."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_window()
        self._build_shell()
        self._setup_status_bar()
        logger.info("MainWindow initialised (Phase 2 UI shell).")

    # ── Window setup ────────────────────────────────────────────────────────

    def _setup_window(self) -> None:
        self.setWindowTitle("AgentShield AI")
        self.setMinimumSize(1100, 700)
        self.resize(1280, 800)

    # ── Shell layout ─────────────────────────────────────────────────────────

    def _build_shell(self) -> None:
        """Build the top-level horizontal layout: sidebar | right panel."""
        root = QWidget()
        root.setStyleSheet(f"background:{T.BG_APP};")
        root_lay = QHBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────────────────
        self._sidebar = Sidebar()
        self._sidebar.page_changed.connect(self._on_page_changed)
        root_lay.addWidget(self._sidebar)

        # ── Right panel (header + content stack) ─────────────────────────────
        right_panel = QWidget()
        right_panel.setStyleSheet(f"background:{T.BG_APP};")
        right_lay = QVBoxLayout(right_panel)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(0)

        self._header = Header()
        right_lay.addWidget(self._header)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"background:{T.BG_APP};")
        right_lay.addWidget(self._stack, stretch=1)

        root_lay.addWidget(right_panel, stretch=1)
        self.setCentralWidget(root)

        # ── Populate stack ───────────────────────────────────────────────────
        self._views: dict[str, QWidget] = {}
        view_classes = [
            ("dashboard",    DashboardView),
            ("agents",       AgentManagerView),
            ("activity",     LiveActivityView),
            ("threats",      ThreatMonitoringView),
            ("approvals",    ApprovalCenterView),
            ("policies",     PolicyManagementView),
            ("audit",        AuditLogsView),
            ("integrations", IntegrationsView),
            ("settings",     SettingsView),
        ]
        for page_id, ViewClass in view_classes:
            view = ViewClass()
            self._views[page_id] = view
            self._stack.addWidget(view)

        # Navigate to dashboard on launch
        self._navigate("dashboard")

    # ── Status bar ───────────────────────────────────────────────────────────

    def _setup_status_bar(self) -> None:
        sb = QStatusBar()
        sb.setSizeGripEnabled(False)
        sb.showMessage(
            f"AgentShield AI  v{_APP_VERSION}  |  "
            "⚠ Demo Mode — no real agents connected — no security enforcement active"
        )
        self.setStatusBar(sb)

    # ── Navigation ───────────────────────────────────────────────────────────

    def _navigate(self, page_id: str) -> None:
        """Switch the stack and update the header for *page_id*."""
        if page_id not in self._views:
            logger.warning("Unknown page_id requested: %s", page_id)
            return
        idx = list(self._views.keys()).index(page_id)
        self._stack.setCurrentIndex(idx)
        self._header.update_page(page_id)

    def _on_page_changed(self, page_id: str) -> None:
        """Slot connected to Sidebar.page_changed signal."""
        self._navigate(page_id)
        logger.debug("Navigated to page: %s", page_id)
