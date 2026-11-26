"""Settings view — application configuration, live backend connection management, and system information."""
from __future__ import annotations

import os
import platform
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from agentshield.core.config import settings
from apps.desktop.components.icons import get_icon
from apps.desktop.components.page_header import PageHeader
from apps.desktop.services.backend_client import backend_client
from apps.desktop.themes.design_tokens import T


def _section_header(text: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(
        f"color:{T.TEXT}; font-size:{T.FS_LG}px; font-weight:700; background:transparent;"
        f"padding-top:{T.SP_2}px;"
    )
    return l


def _row(label: str, widget: QWidget) -> QHBoxLayout:
    h = QHBoxLayout()
    h.setSpacing(T.SP_4)
    lbl = QLabel(label)
    lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_MD}px; min-width:200px; background:transparent;")
    lbl.setFixedWidth(220)
    h.addWidget(lbl)
    h.addWidget(widget, 1)
    h.addStretch()
    return h


def _readonly(value: str) -> QLineEdit:
    le = QLineEdit(value)
    le.setReadOnly(True)
    le.setStyleSheet(
        f"background:{T.SURFACE_ALT}; color:{T.TEXT}; border:1px solid {T.BORDER};"
        f"border-radius:{T.R_MD}px; padding:6px 10px;"
    )
    le.setMaximumWidth(420)
    return le


class SettingsView(QWidget):
    """Application settings — live backend connection configuration and accurate application information."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()
        # Initial check on launch
        QTimer.singleShot(100, lambda: self._test_connection(show_message=False))

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(50, lambda: self._test_connection(show_message=False))

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Settings",
            "Application preferences, live backend connection management, and system information.",
        ))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        content.setStyleSheet(f"background:{T.BG_APP};")
        lay = QVBoxLayout(content)
        lay.setSpacing(T.SP_5)
        lay.setContentsMargins(0, 0, 0, 0)

        # ── Appearance ───────────────────────────────────────────────────────
        lay.addWidget(_section_header("Appearance"))
        app_card = self._card()
        app_lay = QVBoxLayout(app_card)
        app_lay.setSpacing(T.SP_3)

        theme_combo = QComboBox()
        theme_combo.addItems(["Light (Active)", "Dark (Planned)", "System (Planned)"])
        theme_combo.setMaximumWidth(220)
        theme_combo.setEnabled(False)
        app_lay.addLayout(_row("Theme", theme_combo))

        font_combo = QComboBox()
        font_combo.addItems(["System Default", "Inter", "Segoe UI"])
        font_combo.setMaximumWidth(220)
        app_lay.addLayout(_row("Font Family", font_combo))
        app_lay.addLayout(_row("Display Timezone", _readonly("Asia/Kolkata — IST (UTC+05:30)")))
        lay.addWidget(app_card)

        # ── Backend Connection ────────────────────────────────────────────────
        lay.addWidget(_section_header("Backend Connection"))
        backend_card = self._card()
        backend_lay = QVBoxLayout(backend_card)
        backend_lay.setSpacing(T.SP_3)

        # Editable Backend URL
        url_box = QHBoxLayout()
        url_box.setSpacing(T.SP_2)
        self.backend_url_edit = QLineEdit(backend_client.base_url)
        self.backend_url_edit.setPlaceholderText("e.g. http://127.0.0.1:8000")
        self.backend_url_edit.setStyleSheet(
            f"QLineEdit {{ background:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; "
            f"border-radius:{T.R_MD}px; padding:6px 10px; font-size:{T.FS_MD}px; }} "
            f"QLineEdit:focus {{ border-color:{T.PRIMARY}; }}"
        )
        self.backend_url_edit.setMaximumWidth(420)
        url_box.addWidget(self.backend_url_edit)
        backend_lay.addLayout(_row("Backend URL", self.backend_url_edit))

        # API Prefix
        backend_lay.addLayout(_row("API Prefix", _readonly(backend_client.api_prefix)))

        # Status row
        status_widget = QWidget()
        status_box = QVBoxLayout(status_widget)
        status_box.setContentsMargins(0, 0, 0, 0)
        status_box.setSpacing(4)

        self.status_badge = QLabel("● Checking...")
        self.status_badge.setStyleSheet(
            f"color:{T.TEXT_SEC}; background:{T.SURFACE_ALT}; border:1px solid {T.BORDER}; "
            f"border-radius:{T.R_SM}px; padding:4px 10px; font-weight:700; font-size:{T.FS_SM}px;"
        )
        self.status_badge.setFixedWidth(130)
        status_box.addWidget(self.status_badge)

        self.status_detail_lbl = QLabel("Verifying connection to backend service...")
        self.status_detail_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px;")
        self.status_detail_lbl.setWordWrap(True)
        status_box.addWidget(self.status_detail_lbl)

        backend_lay.addLayout(_row("Connection Status", status_widget))

        # Action Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(T.SP_3)

        test_btn = QPushButton("Test Connection")
        test_btn.setIcon(get_icon("refresh", size=14, color="#0F172A"))
        test_btn.setStyleSheet(
            f"QPushButton {{ background-color: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1; "
            f"font-weight: 600; border-radius: 6px; padding: 6px 16px; font-size: 13px; }} "
            f"QPushButton:hover {{ background-color: #E2E8F0; }}"
        )
        test_btn.clicked.connect(lambda: self._test_connection(show_message=True))
        btn_row.addWidget(test_btn)

        apply_btn = QPushButton("Save && Apply URL")
        apply_btn.setIcon(get_icon("check", size=14, color="#FFFFFF"))
        apply_btn.setStyleSheet(
            f"QPushButton {{ background-color: {T.PRIMARY}; color: {T.TEXT_ON_PRIMARY}; border: none; "
            f"font-weight: 600; border-radius: 6px; padding: 6px 16px; font-size: 13px; }} "
            f"QPushButton:hover {{ background-color: {T.PRIMARY_HOVER}; }}"
        )
        apply_btn.clicked.connect(self._apply_backend_url)
        btn_row.addWidget(apply_btn)

        reset_btn = QPushButton("Reset Default")
        reset_btn.setStyleSheet(
            f"QPushButton {{ background-color: {T.SURFACE}; color: {T.TEXT_SEC}; border: 1px solid {T.BORDER}; "
            f"font-weight: 600; border-radius: 6px; padding: 6px 14px; font-size: 13px; }} "
            f"QPushButton:hover {{ background-color: {T.SURFACE_ALT}; color: {T.TEXT}; }}"
        )
        reset_btn.clicked.connect(self._reset_default_url)
        btn_row.addWidget(reset_btn)

        btn_row.addStretch()
        backend_lay.addLayout(btn_row)

        note = QLabel(
            "AgentShield Desktop communicates with the FastAPI security gateway via authenticated REST & WebSocket APIs. "
            "Ensure the backend process is running on the specified host and port."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            f"color:{T.INFO}; background:{T.INFO_BG}; padding:{T.SP_3}px;"
            f"border-radius:{T.R_SM}px; font-size:{T.FS_SM}px;"
        )
        backend_lay.addWidget(note)
        lay.addWidget(backend_card)

        # ── Deployment Mode ───────────────────────────────────────────────────
        lay.addWidget(_section_header("Deployment Mode"))
        dep_card = self._card()
        dep_lay = QVBoxLayout(dep_card)
        dep_lay.setSpacing(T.SP_3)
        dep_lay.addLayout(_row("Deployment Mode",    _readonly(settings.env.value)))
        dep_lay.addLayout(_row("Database Provider",  _readonly("SQLite (aiosqlite) — Local Embedded" if "sqlite" in (settings.effective_database_url or "sqlite") else "PostgreSQL (asyncpg)")))
        dep_lay.addLayout(_row("Log Level",          _readonly(settings.log_level)))
        dep_lay.addLayout(_row("Log Format",         _readonly(settings.log_format)))
        lay.addWidget(dep_card)

        # ── Notifications ─────────────────────────────────────────────────────
        lay.addWidget(_section_header("Notifications"))
        notif_card = self._card()
        notif_lay = QVBoxLayout(notif_card)
        notif_lay.setSpacing(T.SP_3)
        for label, default in [
            ("Critical threat alerts",   True),
            ("Pending approval alerts",  True),
            ("Agent disconnection alerts", False),
            ("Policy violation summary", False),
        ]:
            cb = QCheckBox(label)
            cb.setChecked(default)
            cb.setStyleSheet(f"color:{T.TEXT};")
            notif_lay.addWidget(cb)
        lay.addWidget(notif_card)

        # ── Application Info ──────────────────────────────────────────────────
        lay.addWidget(_section_header("Application Information"))
        info_card = self._card()
        info_lay = QVBoxLayout(info_card)
        info_lay.setSpacing(T.SP_3)
        info_lay.addLayout(_row("Application",            _readonly(settings.app_name)))
        info_lay.addLayout(_row("System Version",          _readonly("v0.1.0 (Production Core)")))
        info_lay.addLayout(_row("System Phase",            _readonly("Phase 10 — Production Runtime Gateway & Firewall")))
        info_lay.addLayout(_row("Protection Architecture", _readonly("FastAPI Core + PySide6 Security Gateway (Asynchronous)")))
        info_lay.addLayout(_row("Firewall Enforcement",    _readonly("Active Runtime Interceptor (Zero-Trust Fail-Closed)")))
        info_lay.addLayout(_row("Audit Integrity",         _readonly("SHA-256 Cryptographic Hash Chain")))
        info_lay.addLayout(_row("Supported Connectors",    _readonly("OpenAI, Claude, LangGraph, CrewAI, Google ADK, Custom REST")))
        info_lay.addLayout(_row("Python Runtime",          _readonly(f"Python {platform.python_version()} ({platform.system()} {platform.machine()})")))
        info_lay.addLayout(_row("Display Timezone",        _readonly("Asia/Kolkata — IST (UTC+05:30)")))
        lay.addWidget(info_card)

        lay.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll)

    def _test_connection(self, show_message: bool = False):
        """Test live connection to backend and update UI."""
        health = backend_client.check_health()
        if health:
            latency = health.get("latency_ms", 0)
            ver = health.get("version", "0.1.0")
            env = health.get("environment", "LOCAL")
            srv = health.get("service", "AgentShield AI")

            self.status_badge.setText("● Connected")
            self.status_badge.setStyleSheet(
                "color: #16A34A; background: #DCFCE7; border: 1px solid #BBF7D0; "
                "border-radius: 6px; padding: 4px 10px; font-weight: 700; font-size: 13px;"
            )
            self.status_detail_lbl.setText(
                f"Connected to {srv} v{ver} [{env}] • Latency: {latency} ms • Target: {backend_client.base_url}"
            )
            self.status_detail_lbl.setStyleSheet("color: #16A34A; font-size: 12px; font-weight: 500;")

            if show_message:
                QMessageBox.information(
                    self,
                    "Connection Successful",
                    f"Successfully reached AgentShield backend!\n\n"
                    f"Target URL: {backend_client.base_url}\n"
                    f"Latency: {latency} ms\n"
                    f"Service: {srv}\n"
                    f"Version: {ver}\n"
                    f"Environment: {env}",
                )
        else:
            self.status_badge.setText("● Disconnected")
            self.status_badge.setStyleSheet(
                "color: #DC2626; background: #FEE2E2; border: 1px solid #FECACA; "
                "border-radius: 6px; padding: 4px 10px; font-weight: 700; font-size: 13px;"
            )
            self.status_detail_lbl.setText(
                f"Backend unreachable at {backend_client.base_url}. Ensure the backend is running with 'uvicorn apps.api.main:app --port 8000'."
            )
            self.status_detail_lbl.setStyleSheet("color: #DC2626; font-size: 12px; font-weight: 500;")

            if show_message:
                QMessageBox.warning(
                    self,
                    "Connection Failed",
                    f"Could not reach AgentShield backend at:\n{backend_client.base_url}\n\n"
                    "Please verify that the server is running and reachable.",
                )

    def _apply_backend_url(self):
        """Save and apply new backend URL."""
        new_url = self.backend_url_edit.text().strip()
        if not new_url:
            QMessageBox.warning(self, "Validation Error", "Backend URL cannot be empty.")
            return

        ok = backend_client.set_base_url(new_url)
        settings.backend_url = backend_client.base_url
        os.environ["AGENTSHIELD_BACKEND_URL"] = backend_client.base_url

        self._test_connection(show_message=True)

    def _reset_default_url(self):
        """Reset backend URL to default localhost:8000."""
        self.backend_url_edit.setText("http://127.0.0.1:8000")
        self._apply_backend_url()

    def _card(self) -> QFrame:
        f = QFrame()
        f.setObjectName("settingsCard")
        f.setStyleSheet(
            f"QFrame#settingsCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_LG}px; padding:{T.SP_3}px; }} QLabel {{ border: none; }}"
        )
        return f
