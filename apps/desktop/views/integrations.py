"""Integrations page — planned/demo integration cards."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea,
    QGridLayout,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.status_badge import StatusBadge
from apps.desktop.services.demo_data      import INTEGRATIONS, IntegrationRecord


class IntegrationsView(QWidget):
    """Integration catalogue — planned statuses only."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Integrations",
            "AI framework connectors and MCP gateway integrations.",
            demo_note="NOT IMPLEMENTED — Integration development planned",
        ))

        # Note banner
        note = QLabel(
            "These integrations are planned for Phase 4+ (SDK) and Phase 5+ (MCP). "
            "No integration packages are installed or configured in Phase 2."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            f"color:{T.INFO}; background:{T.INFO_BG}; border:1px solid {T.INFO};"
            f"border-radius:{T.R_MD}px; padding:{T.SP_4}px; font-size:{T.FS_MD}px;"
        )
        root.addWidget(note)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        inner.setStyleSheet(f"background:{T.BG_APP};")
        grid = QGridLayout(inner)
        grid.setSpacing(T.SP_4)
        grid.setContentsMargins(0, 0, 0, 0)

        for i, integ in enumerate(INTEGRATIONS):
            card = self._make_card(integ)
            grid.addWidget(card, i // 2, i % 2)

        # Fill last row if odd number
        if len(INTEGRATIONS) % 2:
            grid.addWidget(QWidget(), len(INTEGRATIONS) // 2, 1)

        scroll.setWidget(inner)
        root.addWidget(scroll)

    def _make_card(self, integ: IntegrationRecord) -> QFrame:
        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_XL}px; }}"
        )
        lay = QVBoxLayout(card)
        lay.setContentsMargins(T.SP_5, T.SP_5, T.SP_5, T.SP_5)
        lay.setSpacing(T.SP_3)

        # Icon + name row
        top = QHBoxLayout()
        icon_l = QLabel(integ.icon_text)
        icon_l.setStyleSheet("font-size:28px; background:transparent;")
        top.addWidget(icon_l)
        top.addSpacing(T.SP_2)
        name_col = QVBoxLayout(); name_col.setSpacing(1)
        nm = QLabel(integ.name)
        nm.setStyleSheet(f"color:{T.TEXT}; font-weight:700; font-size:{T.FS_LG}px; background:transparent;")
        cat = QLabel(f"Type: {integ.category}")
        cat.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;")
        name_col.addWidget(nm); name_col.addWidget(cat)
        top.addLayout(name_col, 1)
        top.addWidget(StatusBadge(integ.status))
        lay.addLayout(top)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background:{T.BORDER}; border:none; max-height:1px;")
        lay.addWidget(sep)

        desc = QLabel(integ.description)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_MD}px; background:transparent;")
        lay.addWidget(desc)

        return card
