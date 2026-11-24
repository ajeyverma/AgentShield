"""
AgentShield AI — Application Sidebar Navigation (Phase 2).

Dark sidebar with section headers, nav items, and active-state highlight.
"""
from __future__ import annotations
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFrame, QSizePolicy,
)
from apps.desktop.themes.design_tokens import T


NAV_ITEMS = [
    # (page_id, icon, label, section_header_before)
    ("dashboard",         "⊡",  "Dashboard",         "OVERVIEW"),
    ("agents",            "🤖", "Agent Manager",     None),
    ("activity",          "⚡", "Live Activity",     None),
    ("threats",           "🛡",  "Threat Monitoring", None),
    ("approvals",         "✅", "Approval Center",   None),
    ("policies",          "📋", "Policy Management", "MANAGEMENT"),
    ("audit",             "📜", "Audit Logs",        None),
    ("integrations",      "🔗", "Integrations",      None),
    ("settings",          "⚙",  "Settings",          None),
]


class NavButton(QPushButton):
    """Single nav item button."""

    def __init__(self, page_id: str, icon: str, label: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self.setText(f"  {icon}  {label}")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._apply_style(False)

    def _apply_style(self, active: bool):
        if active:
            bg   = T.SIDEBAR_ACTIVE
            text = T.TEXT_ON_DARK
            fw   = "700"
        else:
            bg   = "transparent"
            text = "#94A3B8"
            fw   = "400"
        self.setStyleSheet(
            f"QPushButton {{"
            f"  background:{bg}; color:{text}; border:none;"
            f"  border-radius:{T.R_MD}px;"
            f"  text-align:left; padding:9px 14px;"
            f"  font-size:{T.FS_MD}px; font-weight:{fw};"
            f"}}"
            f"QPushButton:hover {{ background:{'#2D3F55' if not active else bg}; color:{T.TEXT_ON_DARK}; }}"
        )

    def set_active(self, active: bool):
        self._apply_style(active)
        self.setChecked(active)


class Sidebar(QWidget):
    """Fixed-width dark navigation sidebar."""

    page_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(T.SIDEBAR_W)
        self.setStyleSheet(f"background:{T.SIDEBAR_BG}; border:none;")
        self._buttons: dict[str, NavButton] = {}
        self._active_id: str = "dashboard"
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_3, 0, T.SP_3, T.SP_3)
        root.setSpacing(0)

        # ── Logo / Brand ─────────────────────────────────────────────────────
        logo_frame = QWidget()
        logo_frame.setFixedHeight(T.HEADER_H)
        logo_frame.setStyleSheet("background:transparent;")
        logo_lay = QVBoxLayout(logo_frame)
        logo_lay.setContentsMargins(T.SP_2, 0, 0, 0)
        logo_lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        logo_name = QLabel("AgentShield AI")
        logo_name.setStyleSheet(
            f"color:{T.TEXT_ON_DARK}; font-size:{T.FS_LG}px; font-weight:700;"
            "background:transparent;"
        )
        logo_sub = QLabel("Security Gateway")
        logo_sub.setStyleSheet(
            f"color:#64748B; font-size:{T.FS_XS}px; letter-spacing:1px;"
            "text-transform:uppercase; background:transparent;"
        )
        logo_lay.addWidget(logo_name)
        logo_lay.addWidget(logo_sub)
        root.addWidget(logo_frame)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background:#2D3F55; border:none; max-height:1px;")
        root.addWidget(sep)
        root.addSpacing(T.SP_2)

        # ── Nav items ─────────────────────────────────────────────────────────
        for page_id, icon, label, section in NAV_ITEMS:
            if section:
                sec_lbl = QLabel(section)
                sec_lbl.setStyleSheet(
                    f"color:#475569; font-size:{T.FS_XS}px; font-weight:700;"
                    f"letter-spacing:1px; padding:{T.SP_2}px {T.SP_2}px 4px;"
                    "background:transparent;"
                )
                root.addWidget(sec_lbl)

            btn = NavButton(page_id, icon, label)
            btn.clicked.connect(self._on_nav_click)
            self._buttons[page_id] = btn
            root.addWidget(btn)

        root.addStretch()

        # ── Bottom status ─────────────────────────────────────────────────────
        bottom_sep = QFrame()
        bottom_sep.setFrameShape(QFrame.Shape.HLine)
        bottom_sep.setStyleSheet("background:#2D3F55; border:none; max-height:1px;")
        root.addWidget(bottom_sep)
        root.addSpacing(T.SP_2)

        status_lbl = QLabel("⚠ Demo Mode")
        status_lbl.setStyleSheet(
            f"color:{T.WARNING}; font-size:{T.FS_XS}px; font-weight:600;"
            f"background:{T.WARNING_BG}; border-radius:{T.R_SM}px;"
            "padding:4px 8px;"
        )
        root.addWidget(status_lbl, alignment=Qt.AlignmentFlag.AlignCenter)

        # Activate default
        self._set_active("dashboard")

    def _on_nav_click(self):
        btn: NavButton = self.sender()
        self.navigate_to(btn.page_id)

    def navigate_to(self, page_id: str):
        self._set_active(page_id)
        self.page_changed.emit(page_id)

    def set_active(self, page_id: str):
        self._set_active(page_id)

    def _set_active(self, page_id: str):
        if self._active_id in self._buttons:
            self._buttons[self._active_id].set_active(False)
        self._active_id = page_id
        if page_id in self._buttons:
            self._buttons[page_id].set_active(True)
