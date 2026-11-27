"""
AgentShield AI — Desktop Menu Bar Navigation (Clean Desktop Style).

Standard text-based desktop menu bar without emojis, with a pure white background
and absolute zero top padding so menu options sit flush against the top edge.
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
    ("settings",     "Settings"),
]


class TopNavButton(QPushButton):
    """Standard desktop menu item button with absolute zero vertical padding."""

    def __init__(self, page_id: str, label: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self.setText(label)
        self.setCheckable(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(22)
        self._apply_style(False)

    def _apply_style(self, active: bool):
        if active:
            self.setStyleSheet(
                "QPushButton {"
                "  background-color: #E2E8F0 !important;"
                "  color: #0F172A !important;"
                "  border: none !important;"
                "  border-radius: 3px;"
                "  padding: 0px 8px; margin: 0px;"
                "  min-height: 0px; max-height: 22px; height: 22px;"
                "  font-size: 12px; font-weight: 600;"
                "}"
                "QPushButton:hover {"
                "  background-color: #CBD5E1 !important;"
                "  color: #0F172A !important;"
                "}"
                "QPushButton:pressed {"
                "  background-color: #94A3B8 !important;"
                "  color: #0F172A !important;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QPushButton {"
                "  background-color: transparent !important;"
                "  color: #475569 !important;"
                "  border: none !important;"
                "  border-radius: 3px;"
                "  padding: 0px 8px; margin: 0px;"
                "  min-height: 0px; max-height: 22px; height: 22px;"
                "  font-size: 12px; font-weight: 500;"
                "}"
                "QPushButton:hover {"
                "  background-color: #F1F5F9 !important;"
                "  color: #0F172A !important;"
                "}"
                "QPushButton:pressed {"
                "  background-color: #E2E8F0 !important;"
                "  color: #0F172A !important;"
                "}"
            )

    def set_active(self, active: bool):
        self._apply_style(active)


class Header(QFrame):
    """Standard desktop application top menu bar (pure white background)."""

    page_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAutoFillBackground(True)
        self.setStyleSheet(
            "QFrame {"
            "  background-color: #FFFFFF !important;"
            "  border: none !important;"
            "  margin: 0px; padding: 0px;"
            "}"
        )
        self._buttons: dict[str, TopNavButton] = {}
        self._active_id: str = "dashboard"
        self._title_lbl = QLabel()
        self._desc_lbl = QLabel()
        self._build()

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(6, 0, 6, 0)
        root.setSpacing(2)
        root.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.setFixedHeight(24)

        # Menu items (clean text buttons, flush with top)
        for page_id, label in NAV_ITEMS:
            btn = TopNavButton(page_id, label)
            btn.clicked.connect(lambda _, pid=page_id: self._on_button_clicked(pid))
            self._buttons[page_id] = btn
            root.addWidget(btn)

        root.addStretch()

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
        """Maintained for backward compatibility."""
        pass
