"""
AgentShield AI — Application Header (Phase 2).

Shows page title, description, backend connection status, and user placeholder.
"""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QFrame, QPushButton,
)
from apps.desktop.themes.design_tokens import T


PAGE_META: dict[str, tuple[str, str]] = {
    "dashboard":    ("Dashboard",          "Security overview and activity summary"),
    "agents":       ("Agent Manager",      "Registered AI agent connectors"),
    "activity":     ("Live Activity",      "Real-time security evaluation log"),
    "threats":      ("Threat Monitoring",  "Detected anomalies and security events"),
    "approvals":    ("Approval Center",    "Pending human-in-the-loop decisions"),
    "policies":     ("Policy Management",  "Security enforcement policies"),
    "audit":        ("Audit Logs",         "Complete security evaluation audit trail"),
    "integrations": ("Integrations",       "AI framework and MCP connector status"),
    "settings":     ("Settings",           "Application preferences and configuration"),
}


class Header(QWidget):
    """Top application header bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(T.HEADER_H)
        self.setStyleSheet(
            f"background:{T.SURFACE}; border-bottom:1px solid {T.BORDER};"
        )
        self._build()

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(T.SP_6, 0, T.SP_5, 0)
        root.setSpacing(T.SP_3)

        # Page title col
        self._title_lbl = QLabel("Dashboard")
        self._title_lbl.setStyleSheet(
            f"color:{T.TEXT}; font-size:{T.FS_LG}px; font-weight:700; background:transparent;"
        )
        self._desc_lbl = QLabel("Security overview and activity summary")
        self._desc_lbl.setStyleSheet(
            f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;"
        )

        from PySide6.QtWidgets import QVBoxLayout
        title_col = QWidget()
        title_col.setStyleSheet("background:transparent;")
        tc_lay = QVBoxLayout(title_col)
        tc_lay.setContentsMargins(0, 0, 0, 0)
        tc_lay.setSpacing(1)
        tc_lay.addWidget(self._title_lbl)
        tc_lay.addWidget(self._desc_lbl)
        root.addWidget(title_col)

        root.addStretch()

        # Backend status pill
        self._conn_indicator = QLabel("● Not Connected")
        self._conn_indicator.setStyleSheet(
            f"color:{T.TEXT_MUTED}; background:{T.SURFACE_ALT}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_LG}px; padding:4px 12px; font-size:{T.FS_SM}px; font-weight:600;"
        )
        self._conn_indicator.setToolTip(
            "Phase 2 demo mode — Backend not connected.\n"
            "Start the backend and configure AGENTSHIELD_BACKEND_URL."
        )
        root.addWidget(self._conn_indicator)

        # User placeholder
        user_btn = QPushButton("👤 Admin")
        user_btn.setObjectName("secondary")
        user_btn.setFixedHeight(32)
        root.addWidget(user_btn)

    def update_page(self, page_id: str):
        title, desc = PAGE_META.get(page_id, (page_id.title(), ""))
        self._title_lbl.setText(title)
        self._desc_lbl.setText(desc)

    def set_connected(self, connected: bool):
        if connected:
            self._conn_indicator.setText("● Connected")
            self._conn_indicator.setStyleSheet(
                f"color:{T.SUCCESS}; background:{T.SUCCESS_BG}; border:1px solid {T.SUCCESS};"
                f"border-radius:{T.R_LG}px; padding:4px 12px; font-size:{T.FS_SM}px; font-weight:600;"
            )
        else:
            self._conn_indicator.setText("● Not Connected")
            self._conn_indicator.setStyleSheet(
                f"color:{T.TEXT_MUTED}; background:{T.SURFACE_ALT}; border:1px solid {T.BORDER};"
                f"border-radius:{T.R_LG}px; padding:4px 12px; font-size:{T.FS_SM}px; font-weight:600;"
            )
