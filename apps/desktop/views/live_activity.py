"""Live Activity view — Phase 2 demo data only."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QDialog,
    QDialogButtonBox, QGridLayout, QTextEdit,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.data_table   import DataTable
from apps.desktop.components.status_badge import DecisionBadge, RiskBadge, StatusBadge
from apps.desktop.services.demo_data      import ACTIVITY, ActivityRecord
import json


def _activity_detail(rec: ActivityRecord, parent) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(f"Activity Detail — {rec.record_id}")
    dlg.setMinimumWidth(500)
    dlg.setStyleSheet(f"background:{T.SURFACE};")
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
    lay.setSpacing(T.SP_4)

    # Decision + Risk row
    top = QHBoxLayout()
    top.addWidget(DecisionBadge(rec.decision))
    top.addWidget(RiskBadge(rec.risk_level))
    top.addStretch()
    top.addWidget(StatusBadge(rec.status))
    lay.addLayout(top)

    grid = QGridLayout()
    grid.setSpacing(T.SP_2)
    fields = [
        ("Record ID",  rec.record_id),
        ("Timestamp",  rec.timestamp),
        ("Agent",      rec.agent_name),
        ("Agent ID",   rec.agent_id),
        ("Tool",       rec.tool_name),
        ("Operation",  rec.operation),
    ]
    for i, (k, v) in enumerate(fields):
        kl = QLabel(k + ":"); kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        vl = QLabel(v);       vl.setStyleSheet(f"color:{T.TEXT};")
        grid.addWidget(kl, i, 0)
        grid.addWidget(vl, i, 1)
    lay.addLayout(grid)

    # Arguments (JSON prettified)
    args_lbl = QLabel("Arguments (sanitised preview):")
    args_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
    lay.addWidget(args_lbl)
    args_box = QTextEdit()
    args_box.setReadOnly(True)
    args_box.setPlainText(json.dumps(rec.arguments, indent=2))
    args_box.setMaximumHeight(100)
    args_box.setStyleSheet(
        f"background:{T.SURFACE_ALT}; border:1px solid {T.BORDER}; font-family:monospace; font-size:{T.FS_SM}px;"
    )
    lay.addWidget(args_box)

    # Reason
    reason_lbl = QLabel("Reason:")
    reason_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
    lay.addWidget(reason_lbl)
    r_txt = QLabel(rec.reason)
    r_txt.setWordWrap(True)
    r_txt.setStyleSheet(f"color:{T.TEXT};")
    lay.addWidget(r_txt)

    btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    btns.rejected.connect(dlg.reject)
    lay.addWidget(btns)
    dlg.exec()


def _row_from(rec: ActivityRecord) -> list:
    return [rec.timestamp, rec.agent_name, rec.tool_name, rec.operation,
            rec.decision, rec.risk_level, rec.status, rec.record_id]


class LiveActivityView(QWidget):
    """Live activity monitor — demo data only. No real-time events."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records = {r.record_id: r for r in ACTIVITY}
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Live Activity",
            "Security evaluation log for all agent tool calls.",
            demo_note="DEMO DATA — Static snapshot, not live",
        ))

        headers = ["Timestamp", "Agent", "Tool", "Operation",
                   "Decision", "Risk Level", "Status", "ID"]
        rows = [_row_from(r) for r in ACTIVITY]

        self._table = DataTable(
            headers, rows,
            filter_col=4,
            filter_options=["All", "ALLOW", "BLOCK", "ASK_HUMAN"],
            on_select=self._on_row_select,
        )
        # Hide the ID column
        self._table.get_view().setColumnHidden(7, True)
        self._table.get_view().horizontalHeader().setSectionResizeMode(0, self._table.get_view().horizontalHeader().ResizeMode.ResizeToContents)
        root.addWidget(self._table)

    def _on_row_select(self, row_data: list):
        rec_id = row_data[7]
        rec = self._records.get(rec_id)
        if rec:
            _activity_detail(rec, self)
