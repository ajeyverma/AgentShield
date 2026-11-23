"""Reusable stat card widget."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QHBoxLayout
from apps.desktop.themes.design_tokens import T


class StatCard(QFrame):
    """Displays a single KPI with title, value, and optional sub-label."""

    def __init__(
        self,
        title: str,
        value: str,
        sub_label: str = "",
        accent_color: str = T.PRIMARY,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._accent = accent_color
        self.setObjectName("statCard")
        self.setStyleSheet(
            f"QFrame#statCard {{"
            f"  background:{T.SURFACE};"
            f"  border:1px solid {T.BORDER};"
            f"  border-radius:{T.R_LG}px;"
            f"  border-top: 3px solid {accent_color};"
            f"}}"
        )
        self.setMinimumHeight(T.STAT_CARD_H)

        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_4, T.SP_4, T.SP_4, T.SP_3)
        root.setSpacing(4)

        self._title_lbl = QLabel(title)
        self._title_lbl.setStyleSheet(
            f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; font-weight:600;"
            "letter-spacing:0.4px; text-transform:uppercase; background:transparent;"
        )

        self._value_lbl = QLabel(value)
        self._value_lbl.setStyleSheet(
            f"color:{T.TEXT}; font-size:{T.FS_3XL}px; font-weight:700; background:transparent;"
        )

        self._sub_lbl = QLabel(sub_label)
        self._sub_lbl.setStyleSheet(
            f"color:{T.TEXT_MUTED}; font-size:{T.FS_SM}px; background:transparent;"
        )
        self._sub_lbl.setVisible(bool(sub_label))

        root.addWidget(self._title_lbl)
        root.addWidget(self._value_lbl)
        root.addWidget(self._sub_lbl)
        root.addStretch()

    def set_value(self, value: str) -> None:
        self._value_lbl.setText(value)

    def set_sub(self, text: str) -> None:
        self._sub_lbl.setText(text)
        self._sub_lbl.setVisible(bool(text))
