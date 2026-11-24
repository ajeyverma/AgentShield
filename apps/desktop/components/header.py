"""
AgentShield AI — Desktop Menu Bar Navigation (Clean Desktop Style).

Standard text-based desktop menu bar without emojis, with a pure white background
and absolute zero top padding so menu options sit flush against the top edge.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
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
    """Standard desktop menu item button with absolute zero vertical padding."""

    def __init__(self, page_id: str, label: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self.setText(label)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(22)
        self._apply_style(False)

    def _apply_style(self, active: bool):
        if active:
            self.setStyleSheet(
                "QPushButton {"
                f"  background: {T.PRIMARY}; color: #FFFFFF;"
                "  border: none; border-radius: 2px;"
                "  padding: 0px 8px; margin: 0px;"
                "  min-height: 0px; max-height: 22px; height: 22px;"
                "  font-size: 12px; font-weight: 600;"
                "}"
            )
        else:
            self.setStyleSheet(
                "QPushButton {"
                "  background: transparent; color: #334155;"
                "  border: none; border-radius: 2px;"
                "  padding: 0px 8px; margin: 0px;"
                "  min-height: 0px; max-height: 22px; height: 22px;"
                "  font-size: 12px; font-weight: 500;"
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
            "background: #FFFFFF; border: none; margin: 0px; padding: 0px;"
        )
        self._buttons: dict[str, TopNavButton] = {}
        self._active_id: str = "dashboard"
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignmentFlag.AlignTop)

        # ── Row 1: Desktop Menu Bar (Flush Top, Zero Top Padding) ────────────
        menu_bar = QWidget()
        menu_bar.setFixedHeight(24)
        menu_bar.setStyleSheet(
            f"background: #FFFFFF; border-bottom: 1px solid {T.BORDER}; margin: 0px; padding: 0px;"
        )
        menu_lay = QHBoxLayout(menu_bar)
        menu_lay.setContentsMargins(6, 0, 6, 0)
        menu_lay.setSpacing(2)
        menu_lay.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Menu items (clean text buttons, flush with top)
        for page_id, label in NAV_ITEMS:
            btn = TopNavButton(page_id, label)
            btn.clicked.connect(lambda _, pid=page_id: self._on_button_clicked(pid))
            self._buttons[page_id] = btn
            menu_lay.addWidget(btn)

        menu_lay.addStretch()
        root.addWidget(menu_bar)

        # ── Row 2: Page Title & Context Bar ──────────────────────────────────
        context_bar = QWidget()
        context_bar.setFixedHeight(30)
        context_bar.setStyleSheet(
            f"background: #FFFFFF; border-bottom: 1px solid {T.BORDER}; margin: 0px; padding: 0px;"
        )
        ctx_lay = QHBoxLayout(context_bar)
        ctx_lay.setContentsMargins(12, 0, 12, 0)
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
        """Maintained for backward compatibility."""
        pass
