"""
AgentShield AI — Top Navigation Header (Simplified Layout).

Provides full top-menu bar navigation across all 9 application views,
system connection telemetry, and breadcrumb context.
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

NAV_ITEMS: list[tuple[str, str, str]] = [
    ("dashboard",    "⊡", "Dashboard"),
    ("agents",       "🤖", "Agents"),
    ("activity",     "⚡", "Activity"),
    ("threats",      "🛡", "Threats"),
    ("approvals",    "✅", "Approvals"),
    ("policies",     "📋", "Policies"),
    ("audit",        "📜", "Audit"),
    ("integrations", "🔗", "Integrations"),
    ("settings",     "⚙", "Settings"),
]


class TopNavButton(QPushButton):
    """Top navigation tab button."""

    def __init__(self, page_id: str, icon: str, label: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self.setText(f"{icon}  {label}")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(34)
        self._apply_style(False)

    def _apply_style(self, active: bool):
        if active:
            self.setStyleSheet(
                f"QPushButton {{"
                f"  background:{T.PRIMARY}; color:{T.TEXT_ON_PRIMARY};"
                f"  border:1px solid {T.PRIMARY}; border-radius:{T.R_MD}px;"
                f"  padding: 6px 12px; font-size:{T.FS_SM}px; font-weight:700;"
                f"}}"
            )
        else:
            self.setStyleSheet(
                f"QPushButton {{"
                f"  background:transparent; color:{T.TEXT_SEC};"
                f"  border:1px solid transparent; border-radius:{T.R_MD}px;"
                f"  padding: 6px 12px; font-size:{T.FS_SM}px; font-weight:600;"
                f"}}"
                f"QPushButton:hover {{"
                f"  background:{T.SURFACE_ALT}; color:{T.TEXT};"
                f"  border:1px solid {T.BORDER};"
                f"}}"
            )

    def set_active(self, active: bool):
        self._apply_style(active)
        self.setChecked(active)


class Header(QWidget):
    """Top navigation and application header bar."""

    page_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"background:{T.SURFACE}; border-bottom:1px solid {T.BORDER};"
        )
        self._buttons: dict[str, TopNavButton] = {}
        self._active_id: str = "dashboard"
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Row 1: Primary Top Menu Bar ──────────────────────────────────────
        top_bar = QWidget()
        top_bar.setFixedHeight(54)
        top_bar.setStyleSheet(f"background:{T.SURFACE}; border-bottom:1px solid {T.BORDER};")
        top_lay = QHBoxLayout(top_bar)
        top_lay.setContentsMargins(T.SP_4, 0, T.SP_4, 0)
        top_lay.setSpacing(T.SP_2)

        # Brand / Logo
        brand_frame = QWidget()
        brand_frame.setStyleSheet("background:transparent;")
        brand_lay = QHBoxLayout(brand_frame)
        brand_lay.setContentsMargins(0, 0, T.SP_3, 0)
        brand_lay.setSpacing(T.SP_2)

        logo_title = QLabel("🛡️ AgentShield")
        logo_title.setStyleSheet(
            f"color:{T.TEXT}; font-size:{T.FS_LG}px; font-weight:800; background:transparent;"
        )
        badge = QLabel("GATEWAY")
        badge.setStyleSheet(
            f"color:{T.PRIMARY}; background:{T.PRIMARY_LIGHT}; border:1px solid {T.PRIMARY};"
            f"border-radius:{T.R_SM}px; padding:2px 6px; font-size:9px; font-weight:700;"
        )
        brand_lay.addWidget(logo_title)
        brand_lay.addWidget(badge)
        top_lay.addWidget(brand_frame)

        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.VLine)
        sep1.setStyleSheet(f"color:{T.BORDER}; background:{T.BORDER}; max-width:1px;")
        sep1.setFixedHeight(24)
        top_lay.addWidget(sep1)
        top_lay.addSpacing(T.SP_2)

        # Navigation Options in the Top Menu Bar
        for page_id, icon, label in NAV_ITEMS:
            btn = TopNavButton(page_id, icon, label)
            btn.clicked.connect(lambda _, pid=page_id: self._on_button_clicked(pid))
            self._buttons[page_id] = btn
            top_lay.addWidget(btn)

        top_lay.addStretch()

        # Backend Connection Indicator
        self._conn_indicator = QLabel("● Not Connected")
        self._conn_indicator.setStyleSheet(
            f"color:{T.TEXT_MUTED}; background:{T.SURFACE_ALT}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_LG}px; padding:4px 12px; font-size:{T.FS_SM}px; font-weight:600;"
        )
        self._conn_indicator.setToolTip(
            "Backend connection status.\n"
            "Green indicates an active link to the AgentShield FastAPI Security Gateway."
        )
        top_lay.addWidget(self._conn_indicator)

        # User Button
        user_btn = QPushButton("👤 Admin")
        user_btn.setObjectName("secondary")
        user_btn.setFixedHeight(32)
        user_btn.setStyleSheet(
            f"QPushButton {{"
            f"  background:{T.SURFACE_ALT}; color:{T.TEXT}; border:1px solid {T.BORDER};"
            f"  border-radius:{T.R_MD}px; padding:4px 10px; font-size:{T.FS_SM}px; font-weight:600;"
            f"}}"
            f"QPushButton:hover {{ background:{T.BORDER}; }}"
        )
        top_lay.addWidget(user_btn)
        root.addWidget(top_bar)

        # ── Row 2: Sub-Header Context Bar ────────────────────────────────────
        context_bar = QWidget()
        context_bar.setFixedHeight(38)
        context_bar.setStyleSheet(f"background:{T.SURFACE_ALT}; border-bottom:1px solid {T.BORDER};")
        ctx_lay = QHBoxLayout(context_bar)
        ctx_lay.setContentsMargins(T.SP_5, 0, T.SP_5, 0)
        ctx_lay.setSpacing(T.SP_2)

        self._title_lbl = QLabel("Dashboard")
        self._title_lbl.setStyleSheet(
            f"color:{T.TEXT}; font-size:{T.FS_MD}px; font-weight:700; background:transparent;"
        )
        ctx_div = QLabel("—")
        ctx_div.setStyleSheet(f"color:{T.TEXT_MUTED}; background:transparent;")

        self._desc_lbl = QLabel("Security overview and activity summary")
        self._desc_lbl.setStyleSheet(
            f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;"
        )

        ctx_lay.addWidget(self._title_lbl)
        ctx_lay.addWidget(ctx_div)
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
