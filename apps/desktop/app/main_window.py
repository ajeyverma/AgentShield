"""
AgentShield AI — Desktop Application Main Window (Phase 3).

Integrates sidebar navigation, header bar, and a QStackedWidget containing
all nine content views. Includes non-blocking background connection monitoring
to communicate with the FastAPI backend.
"""
from __future__ import annotations

import logging

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.components.header import Header
from apps.desktop.components.sidebar import NAV_ITEMS, Sidebar
from apps.desktop.config.settings import BACKEND_URL
from apps.desktop.services.backend_client import backend_client
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

_APP_VERSION = "0.3.0"


class HealthSignals(QObject):
    """Signals for background health checking."""
    health_result = Signal(bool)


class HealthCheckTask(QRunnable):
    """Background task to query backend health without blocking the Qt UI thread."""

    def __init__(self, signals: HealthSignals) -> None:
        super().__init__()
        self.signals = signals

    def run(self) -> None:
        try:
            health = backend_client.check_health()
            try:
                self.signals.health_result.emit(health is not None)
            except RuntimeError:
                pass
        except Exception:
            try:
                self.signals.health_result.emit(False)
            except RuntimeError:
                pass


class MainWindow(QMainWindow):
    """AgentShield AI main application window (Phase 3 — connected UI shell)."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_window()
        self._build_shell()
        self._setup_status_bar()
        self._setup_backend_monitor()
        logger.info("MainWindow initialised (Phase 3).")

    # ── Window setup ────────────────────────────────────────────────────────

    def _setup_window(self) -> None:
        self.setWindowTitle("AgentShield AI")
        self.setMinimumSize(1050, 560)
        self.resize(1180, 640)

    # ── Shell layout ─────────────────────────────────────────────────────────

    def _build_shell(self) -> None:
        """Build the clean top-navigation layout: Top Menu Bar Header | Content Stack."""
        root = QWidget()
        root.setObjectName("centralRoot")
        root.setStyleSheet(f"QWidget#centralRoot {{ background:{T.BG_APP}; }}")
        root_lay = QVBoxLayout(root)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        # ── Top Navigation Header ────────────────────────────────────────────
        self._header = Header()
        self._header.setStyleSheet("background-color: #FFFFFF !important; border: none !important; margin: 0px; padding: 0px;")
        self._header.page_changed.connect(self._on_page_changed)
        root_lay.addWidget(self._header)

        # ── Full-width Content Stack ─────────────────────────────────────────
        self._stack = QStackedWidget()
        self._stack.setObjectName("contentStack")
        self._stack.setStyleSheet(f"QStackedWidget#contentStack {{ background:{T.BG_APP}; }}")
        root_lay.addWidget(self._stack, stretch=1)

        self.setCentralWidget(root)

        # Retain _sidebar instance for backward compatibility (hidden)
        self._sidebar = Sidebar()
        self._sidebar.hide()
        self._sidebar.page_changed.connect(self._on_page_changed)

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
        self._status_bar = QStatusBar()
        self._status_bar.setSizeGripEnabled(False)
        self._status_bar.setStyleSheet(
            f"QStatusBar {{"
            f"  background: {T.SURFACE}; border-top: 1px solid {T.BORDER};"
            f"  color: {T.TEXT_SEC}; font-size: 11px; padding: 2px 8px;"
            f"}}"
        )

        # Permanent plain text label on the right side of the bottom status bar
        self._status_tz_lbl = QLabel("Timezone: IST (UTC+05:30)")
        self._status_tz_lbl.setStyleSheet(
            f"color: {T.TEXT_SEC}; font-size: 11px; font-weight: 500; padding: 0px 8px;"
        )
        self._status_bar.addPermanentWidget(self._status_tz_lbl)

        self._status_user_lbl = QLabel("Admin")
        self._status_user_lbl.setStyleSheet(
            f"color: {T.TEXT_SEC}; font-size: 11px; font-weight: 500; padding: 0px 8px;"
        )
        self._status_bar.addPermanentWidget(self._status_user_lbl)

        self._update_status_bar(connected=False)
        self.setStatusBar(self._status_bar)

    def _update_status_bar(self, connected: bool) -> None:
        if connected:
            self._status_bar.showMessage(
                f"AgentShield AI v{_APP_VERSION}  |  Connected to backend: {BACKEND_URL}"
            )
        else:
            self._status_bar.showMessage(
                f"AgentShield AI v{_APP_VERSION}  |  Disconnected from backend — Offline"
            )

    # ── Background Backend Monitoring ────────────────────────────────────────

    def _setup_backend_monitor(self) -> None:
        """Start a periodic health check that runs on a background worker thread."""
        self._health_signals = HealthSignals()
        self._health_signals.health_result.connect(self._on_health_result)

        # Check immediately
        self._trigger_health_check()

        # Check periodically every 15 seconds
        self._health_timer = QTimer(self)
        self._health_timer.timeout.connect(self._trigger_health_check)
        self._health_timer.start(15000)

    def _trigger_health_check(self) -> None:
        task = HealthCheckTask(self._health_signals)
        QThreadPool.globalInstance().start(task)

    def _on_health_result(self, is_alive: bool) -> None:
        """Slot invoked on Qt main thread when background health check finishes."""
        self._header.set_connected(is_alive)
        self._update_status_bar(is_alive)
        logger.debug("Backend health check completed: connected=%s", is_alive)

    # ── Navigation ───────────────────────────────────────────────────────────

    def _navigate(self, page_id: str) -> None:
        """Switch the stack and update the header for *page_id*."""
        if page_id not in self._views:
            logger.warning("Unknown page_id requested: %s", page_id)
            return
        idx = list(self._views.keys()).index(page_id)
        self._stack.setCurrentIndex(idx)
        self._header.update_page(page_id)
        view = self._views[page_id]
        if hasattr(view, "refresh_data"):
            try:
                view.refresh_data()
            except Exception as exc:
                logger.debug("View refresh failed: %s", exc)

    def _on_page_changed(self, page_id: str) -> None:
        """Slot connected to Sidebar.page_changed signal."""
        self._navigate(page_id)
        logger.debug("Navigated to page: %s", page_id)
