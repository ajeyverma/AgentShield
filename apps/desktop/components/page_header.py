"""Page header component with title, description, and optional actions."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
)
from apps.desktop.themes.design_tokens import T


class PageHeader(QWidget):
    """Renders the top section of a view: title + description + action buttons."""

    def __init__(
        self,
        title: str,
        description: str = "",
        demo_note: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setStyleSheet("background:transparent;")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(2)

        # Title row
        title_row = QHBoxLayout()
        title_row.setSpacing(T.SP_3)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"color:{T.TEXT}; font-size:{T.FS_XL}px; font-weight:700; background:transparent; border:none;"
        )
        title_row.addWidget(title_lbl)

        if demo_note:
            note = QLabel(f"⚠ {demo_note}")
            note.setStyleSheet(
                f"color:{T.WARNING}; background:{T.WARNING_BG};"
                f"border:none; border-radius:{T.R_SM}px;"
                f"padding:2px 10px; font-size:{T.FS_SM}px; font-weight:600;"
            )
            title_row.addWidget(note)

        title_row.addStretch()
        root.addLayout(title_row)

        if description:
            desc_lbl = QLabel(description)
            desc_lbl.setStyleSheet(
                f"color:{T.TEXT_SEC}; font-size:{T.FS_MD}px; background:transparent; border:none;"
            )
            desc_lbl.setWordWrap(True)
            root.addWidget(desc_lbl)
