"""Empty state widget displayed when a list has no items."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from apps.desktop.themes.design_tokens import T


class EmptyState(QWidget):
    def __init__(self, icon: str = "📭", message: str = "No items found.", subtext: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(T.SP_2)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size:40px; background:transparent;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        msg_lbl = QLabel(message)
        msg_lbl.setStyleSheet(
            f"color:{T.TEXT}; font-size:{T.FS_MD}px; font-weight:600; background:transparent;"
        )
        msg_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(icon_lbl)
        layout.addWidget(msg_lbl)

        if subtext:
            sub_lbl = QLabel(subtext)
            sub_lbl.setStyleSheet(
                f"color:{T.TEXT_MUTED}; font-size:{T.FS_SM}px; background:transparent;"
            )
            sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(sub_lbl)
