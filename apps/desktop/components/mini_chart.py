"""
Lightweight native chart widgets using QPainter.
No external chart library required.
"""
from __future__ import annotations
import math
from typing import Sequence
from PySide6.QtCore import Qt, QRect, QRectF, QPointF
from PySide6.QtGui import QPainter, QColor, QPen, QBrush, QPainterPath, QFont
from PySide6.QtWidgets import QWidget
from apps.desktop.themes.design_tokens import T


class BarChartWidget(QWidget):
    """
    Simple vertical bar chart with optional two series (allow/block trend).
    series1_data, series2_data: lists of float values.
    labels: x-axis labels.
    """

    def __init__(
        self,
        series1_data: Sequence[float],
        series2_data: Sequence[float] | None = None,
        labels: Sequence[str] | None = None,
        series1_color: str = T.CHART_ALLOW,
        series2_color: str = T.CHART_BLOCK,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._s1 = list(series1_data)
        self._s2 = list(series2_data) if series2_data else []
        self._labels = list(labels) if labels else []
        self._c1 = QColor(series1_color)
        self._c2 = QColor(series2_color)
        self.setMinimumHeight(140)

    def update_data(
        self,
        series1_data: Sequence[float],
        series2_data: Sequence[float] | None = None,
    ) -> None:
        self._s1 = list(series1_data)
        self._s2 = list(series2_data) if series2_data else []
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        pad_l, pad_r, pad_t, pad_b = 36, 12, 12, 32

        if not self._s1:
            return

        n = len(self._s1)
        all_vals = self._s1 + self._s2
        max_val = max(all_vals) if all_vals else 1
        if max_val == 0:
            max_val = 1

        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b
        bar_area = chart_w / n

        dual = bool(self._s2)
        bar_w = int(bar_area * (0.35 if dual else 0.55))

        # Draw y-axis gridlines
        painter.setPen(QPen(QColor(T.BORDER), 1, Qt.PenStyle.DashLine))
        for i in range(5):
            y = pad_t + int(chart_h * i / 4)
            painter.drawLine(pad_l, y, w - pad_r, y)

        # Draw bars
        for i, v1 in enumerate(self._s1):
            x = pad_l + int(i * bar_area)
            bh = int(chart_h * v1 / max_val)
            by = pad_t + chart_h - bh

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(self._c1))
            painter.drawRoundedRect(x + 4, by, bar_w, bh, 3, 3)

            if dual and i < len(self._s2):
                v2 = self._s2[i]
                bh2 = int(chart_h * v2 / max_val)
                by2 = pad_t + chart_h - bh2
                painter.setBrush(QBrush(self._c2))
                painter.drawRoundedRect(x + 4 + bar_w + 2, by2, bar_w, bh2, 3, 3)

        # X labels
        if self._labels:
            painter.setPen(QPen(QColor(T.TEXT_MUTED)))
            font = QFont()
            font.setPointSize(T.FS_XS)
            painter.setFont(font)
            for i, lbl in enumerate(self._labels[:n]):
                x = pad_l + int(i * bar_area)
                painter.drawText(
                    QRect(x, h - pad_b + 4, int(bar_area), pad_b - 4),
                    Qt.AlignmentFlag.AlignCenter, str(lbl),
                )

        painter.end()


class DonutChartWidget(QWidget):
    """Simple donut/pie chart with legend."""

    def __init__(
        self,
        segments: list[tuple[str, float, str]],  # (label, value, color)
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._segs = segments
        self.setMinimumSize(200, 160)

    def update_data(self, segments: list[tuple[str, float, str]]) -> None:
        self._segs = segments
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        legend_w = 110
        chart_size = min(w - legend_w - 16, h - 16)
        cx = chart_size // 2 + 8
        cy = h // 2
        outer_r = chart_size // 2
        inner_r = int(outer_r * 0.58)

        total = sum(v for _, v, _ in self._segs)
        if total == 0:
            total = 1

        start_angle = 90 * 16  # start at top (Qt uses 1/16 degrees)
        rect = QRectF(cx - outer_r, cy - outer_r, outer_r * 2, outer_r * 2)

        for label, value, color in self._segs:
            span = int(360 * 16 * value / total)
            painter.setBrush(QBrush(QColor(color)))
            painter.setPen(QPen(QColor("#FFFFFF"), 2))
            painter.drawPie(rect, start_angle, -span)
            start_angle -= span

        # Inner circle (donut hole)
        painter.setBrush(QBrush(QColor(T.SURFACE)))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPointF(cx, cy), inner_r, inner_r)

        # Legend
        font = QFont()
        font.setPointSize(T.FS_SM)
        painter.setFont(font)
        lx = cx + outer_r + 16
        ly = cy - len(self._segs) * 11

        for label, value, color in self._segs:
            pct = f"{value/total*100:.0f}%"
            painter.setBrush(QBrush(QColor(color)))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(lx, ly, 10, 10, 2, 2)
            painter.setPen(QPen(QColor(T.TEXT_SEC)))
            painter.drawText(lx + 14, ly + 10, f"{label} {pct}")
            ly += 22

        painter.end()
