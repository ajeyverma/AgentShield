"""Settings view — loads from Phase 1 configuration."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea,
    QComboBox, QLineEdit, QCheckBox,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from agentshield.core.config import settings


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
        f"background:{T.SURFACE_ALT}; color:{T.TEXT_SEC}; border:none;"
        f"border-radius:{T.R_MD}px; padding:6px 10px;"
    )
    le.setMaximumWidth(380)
    return le


class SettingsView(QWidget):
    """Application settings — reads from Phase 1 config. No credential storage."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Settings",
            "Application preferences and backend connection configuration.",
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
        lay.addWidget(app_card)

        # ── Backend Connection ────────────────────────────────────────────────
        lay.addWidget(_section_header("Backend Connection"))
        backend_card = self._card()
        backend_lay = QVBoxLayout(backend_card)
        backend_lay.setSpacing(T.SP_3)
        backend_lay.addLayout(_row("Backend URL", _readonly(settings.backend_url)))
        backend_lay.addLayout(_row("API Prefix",  _readonly(settings.api_prefix)))
        backend_lay.addLayout(_row("Connection Status",
            _readonly("⚠ Not Connected — Backend not running (Phase 2)")))

        note = QLabel(
            "To connect to the backend: start it with  uvicorn apps.api.main:app  "
            "and set AGENTSHIELD_BACKEND_URL in your .env file."
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
        dep_lay.addLayout(_row("Current Mode",    _readonly(settings.env.value)))
        dep_lay.addLayout(_row("Log Level",        _readonly(settings.log_level)))
        dep_lay.addLayout(_row("Log Format",       _readonly(settings.log_format)))
        lay.addWidget(dep_card)

        # ── Notifications ─────────────────────────────────────────────────────
        lay.addWidget(_section_header("Notifications"))
        notif_card = self._card()
        notif_lay = QVBoxLayout(notif_card)
        notif_lay.setSpacing(T.SP_3)
        for label, default in [
            ("Critical threat alerts",   True),
            ("Pending approval alerts",  True),
            ("Agent disconnection",      False),
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
        info_lay.addLayout(_row("Application",  _readonly(settings.app_name)))
        info_lay.addLayout(_row("Version",      _readonly(settings.app_version)))
        info_lay.addLayout(_row("Phase",        _readonly("Phase 2 — Desktop UI")))
        info_lay.addLayout(_row("Python",       _readonly(__import__("platform").python_version())))
        lay.addWidget(info_card)

        lay.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll)

    def _card(self) -> QFrame:
        f = QFrame()
        f.setObjectName("settingsCard")
        f.setStyleSheet(
            f"QFrame#settingsCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_LG}px; padding:{T.SP_3}px; }} QLabel {{ border: none; }}"
        )
        return f
