"""
AgentShield AI — Desktop Menu Bar Navigation (Clean Desktop Style).

Standard text-based desktop menu bar without emojis, providing fast navigation,
connection status indicator, and context header.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.themes.design_tokens import T

PAGE_META: dict[str, tuple[str, str]] = {
    "dashboard":    ("Dashboard",          "Security overview and activity summary"),
    "agents":       ("Agent Manager",      "Registered AI agent connectors and permissions"),
    "activity":     ("Live Activity",      "Real-time security evaluation feed and audit events"),
    "threats":      ("Threat Monitoring",  "Detected anomalies, attacks, and risk analysis"),
    "approvals":    ("Approval Center",    "Pending human-in-the-loop decisions and authorizations"),
    "policies":     ("Policy Management",  "Security rules, enforcement boundaries, and simulation"),
    "audit":        ("Audit Logs",         "Complete cryptographic security evaluation audit trail"),
    "integrations": ("Integrations",       "AI framework and Model Context Protocol (MCP) gateways"),
    "settings":     ("Settings",           "Application configuration and backend connection settings"),
}

# Standard text-only navigation menu items (zero emojis)
NAV_ITEMS: list[tuple[str, str]] = [
    ("dashboard",    "Dashboard"),
    ("agents",       "Agents"),
    ("activity",     "Activity"),
    ("threats",      "Threats"),
    ("approvals",    "Approvals"),
    ("policies",     "Policies"),
    ("audit",        "Audit Logs"),
    ("integrations", "Integrations"),
    ("settings",     "Settings"),
]


class TopNavButton(QPushButton):
    """Standard desktop menu item button (text-only, flat)."""

    def __init__(self, page_id: str, label: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self.setText(label)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(28)
        self._apply_style(False)

    def _apply_style(self, active: bool):
        if active:
            self.setStyleSheet(
                "QPushButton {"
                f"  background: {T.PRIMARY}; color: #FFFFFF;"
                "  border: none; border-radius: 4px;"
                "  padding: 4px 10px; font-size: 12px; font-weight: 600;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QPushButton {"
                "  background: transparent; color: #334155;"
                "  border: none; border-radius: 4px;"
                "  padding: 4px 10px; font-size: 12px; font-weight: 500;"
                "}"
                "QPushButton:hover {"
                "  background: #E2E8F0; color: #0F172A;"
                "}"
            )

    def set_active(self, active: bool):
        self._apply_style(active)
        self.setChecked(active)


class Header(QWidget):
    """Standard desktop application top menu bar and context header."""

    page_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"background: {T.SURFACE}; border-bottom: 1px solid {T.BORDER};"
        )
        self._buttons: dict[str, TopNavButton] = {}
        self._active_id: str = "dashboard"
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Row 1: Desktop Application Menu Bar ──────────────────────────────
        menu_bar = QWidget()
        menu_bar.setFixedHeight(36)
        menu_bar.setStyleSheet(
            f"background: #F8FAFC; border-bottom: 1px solid {T.BORDER};"
        )
        menu_lay = QHBoxLayout(menu_bar)
        menu_lay.setContentsMargins(12, 0, 12, 0)
        menu_lay.setSpacing(4)

        # Menu items (clean text buttons)
        for page_id, label in NAV_ITEMS:
            btn = TopNavButton(page_id, label)
            btn.clicked.connect(lambda _, pid=page_id: self._on_button_clicked(pid))
            self._buttons[page_id] = btn
            menu_lay.addWidget(btn)

        menu_lay.addStretch()

        # Connection status badge (text only, clean)
        self._conn_indicator = QLabel("Connected")
        self._conn_indicator.setStyleSheet(
            f"color: {T.SUCCESS}; background: {T.SUCCESS_BG}; border: 1px solid {T.SUCCESS};"
            "border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 600;"
        )
        menu_lay.addWidget(self._conn_indicator)

        # User profile button (text only, clean)
        user_btn = QPushButton("Admin")
        user_btn.setFixedHeight(24)
        user_btn.setStyleSheet(
            "QPushButton {"
            f"  background: transparent; color: {T.TEXT_SEC}; border: 1px solid {T.BORDER};"
            "  border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 500;"
            "}"
            f"QPushButton:hover {{ background: {T.BORDER}; color: {T.TEXT}; }}"
        )
        menu_lay.addWidget(user_btn)
        root.addWidget(menu_bar)

        # ── Row 2: Page Title & Context Bar ──────────────────────────────────
        context_bar = QWidget()
        context_bar.setFixedHeight(34)
        context_bar.setStyleSheet(
            f"background: {T.SURFACE}; border-bottom: 1px solid {T.BORDER};"
        )
        ctx_lay = QHBoxLayout(context_bar)
        ctx_lay.setContentsMargins(16, 0, 16, 0)
        ctx_lay.setSpacing(8)

        self._title_lbl = QLabel("Dashboard")
        self._title_lbl.setStyleSheet(
            f"color: {T.TEXT}; font-size: 13px; font-weight: 700;"
        )
        ctx_sep = QLabel("|")
        ctx_sep.setStyleSheet(f"color: {T.TEXT_MUTED}; font-size: 12px;")

        self._desc_lbl = QLabel("Security overview and activity summary")
        self._desc_lbl.setStyleSheet(
            f"color: {T.TEXT_SEC}; font-size: 12px;"
        )

        ctx_lay.addWidget(self._title_lbl)
        ctx_lay.addWidget(ctx_sep)
        ctx_lay.addWidget(self._desc_lbl)
        ctx_lay.addStretch()

        root.addWidget(context_bar)

        # Set default active
        self._set_active_button("dashboard")

    def _on_button_clicked(self, page_id: str):
        self._set_active_button(page_id)
        self.page_changed.emit(page_id)

    def _set_active_button(self, page_id: str):
        if self._active_id in self._buttons:
            self._buttons[self._active_id].set_active(False)
        self._active_id = page_id
        if page_id in self._buttons:
            self._buttons[page_id].set_active(True)

    def update_page(self, page_id: str):
        title, desc = PAGE_META.get(page_id, (page_id.title(), ""))
        self._title_lbl.setText(title)
        self._desc_lbl.setText(desc)
        self._set_active_button(page_id)

    def set_connected(self, connected: bool):
        if connected:
            self._conn_indicator.setText("Connected")
            self._conn_indicator.setStyleSheet(
                f"color: {T.SUCCESS}; background: {T.SUCCESS_BG}; border: 1px solid {T.SUCCESS};"
                "border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 600;"
            )
        else:
            self._conn_indicator.setText("Disconnected")
            self._conn_indicator.setStyleSheet(
                f"color: {T.TEXT_MUTED}; background: {T.SURFACE_ALT}; border: 1px solid {T.BORDER};"
                "border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 600;"
            )
