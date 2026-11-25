"""Empty state widget displayed when a list has no items."""
from __future__ import annotations
from typing import Any
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.icons import get_pixmap


class EmptyState(QWidget):
    def __init__(self, icon: Any = "📭", message: str = "No items found.", subtext: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(T.SP_2)

        icon_lbl = QLabel()
        if isinstance(icon, QPixmap):
            icon_lbl.setPixmap(icon)
        elif isinstance(icon, str) and icon in ("agent", "shield", "alert", "refresh", "trash"):
            icon_lbl.setPixmap(get_pixmap(icon, size=48, color="#94A3B8"))
        else:
            icon_lbl.setText(str(icon))
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
