"""Live Activity view — Phase 6 with Controlled Tool Execution Integration & Demo Fallback."""
from __future__ import annotations
import json
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QDialog,
    QDialogButtonBox, QGridLayout, QTextEdit,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.data_table   import DataTable
from apps.desktop.components.status_badge import DecisionBadge, RiskBadge, StatusBadge
from apps.desktop.services.backend_client import backend_client


def _activity_detail(rec: dict | ActivityRecord, parent) -> None:
    dlg = QDialog(parent)
    is_dict = isinstance(rec, dict)
    rec_id = rec.get("execution_id") or rec.get("id") if is_dict else rec.record_id
    dlg.setWindowTitle(f"Activity / Execution Detail — {str(rec_id)[:16]}")
    dlg.setMinimumWidth(540)
    dlg.setStyleSheet(f"background:{T.SURFACE};")
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
    lay.setSpacing(T.SP_4)

    # Decision + Risk row
    decision_val = rec.get("decision", "ALLOW") if is_dict else rec.decision
    status_val = rec.get("status", "COMPLETED") if is_dict else rec.status
    risk_val = rec.get("risk_level", "LOW") if is_dict else rec.risk_level

    top = QHBoxLayout()
    top.addWidget(DecisionBadge(decision_val))
    top.addWidget(RiskBadge(risk_val))
    top.addStretch()
    top.addWidget(StatusBadge(status_val))
    lay.addLayout(top)

    grid = QGridLayout()
    grid.setSpacing(T.SP_2)
    if is_dict:
        fields = [
            ("Execution ID", str(rec.get("execution_id") or rec.get("id"))),
            ("Created At",   str(rec.get("created_at", ""))[:19]),
            ("Agent ID",     str(rec.get("agent_id", ""))[:12]),
            ("Tool",         str(rec.get("tool_name", ""))),
            ("Action",       str(rec.get("action_name", ""))),
            ("Duration",     f"{rec.get('duration_ms', 0)} ms"),
        ]
    else:
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

    # Result or Arguments
    if is_dict and rec.get("result") is not None:
        args_lbl = QLabel("Execution Result:")
        args_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(args_lbl)
        args_box = QTextEdit()
        args_box.setReadOnly(True)
        args_box.setPlainText(json.dumps(rec.get("result"), indent=2))
        args_box.setMaximumHeight(100)
        args_box.setStyleSheet(
            f"background:{T.SURFACE_ALT}; border:none; border-radius:{T.R_SM}px; font-family:monospace; font-size:{T.FS_SM}px; padding:6px 10px;"
        )
        lay.addWidget(args_box)
    elif not is_dict:
        args_lbl = QLabel("Arguments (sanitised preview):")
        args_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(args_lbl)
        args_box = QTextEdit()
        args_box.setReadOnly(True)
        args_box.setPlainText(json.dumps(rec.arguments, indent=2))
        args_box.setMaximumHeight(100)
        args_box.setStyleSheet(
            f"background:{T.SURFACE_ALT}; border:none; border-radius:{T.R_SM}px; font-family:monospace; font-size:{T.FS_SM}px; padding:6px 10px;"
        )
        lay.addWidget(args_box)

    # Error or Reason
    reason_str = rec.get("error_message") if is_dict else rec.reason
    if reason_str:
        reason_lbl = QLabel("Error / Rejection Reason:")
        reason_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(reason_lbl)
        r_txt = QLabel(reason_str)
        r_txt.setWordWrap(True)
        r_txt.setStyleSheet(f"color:{T.TEXT};")
        lay.addWidget(r_txt)

    btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    btns.rejected.connect(dlg.reject)
    lay.addWidget(btns)
    dlg.exec()


class LiveActivityView(QWidget):
    """Live activity monitor — displays live gateway executions."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records = {}
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        live_executions = []
        if backend_client.is_connected:
            resp = backend_client.list_executions(size=50)
            if resp and "items" in resp and resp["items"]:
                live_executions = resp["items"]

        root.addWidget(PageHeader(
            "Live Activity",
            "Security evaluation and controlled gateway execution log.",
        ))

        headers = ["Timestamp", "Agent", "Tool", "Operation",
                   "Decision", "Risk Level", "Status", "ID"]

        rows = [_row_from_execution(r) for r in live_executions]
        for r in live_executions:
            eid = str(r.get("execution_id") or r.get("id"))
            self._records[eid] = r

        self._table = DataTable(
            headers, rows,
            filter_col=4,
            filter_options=["All", "ALLOW", "BLOCK", "ASK_HUMAN"],
            on_select=self._on_row_select,
        )
        self._table.get_view().setColumnHidden(7, True)
        self._table.get_view().horizontalHeader().setSectionResizeMode(0, self._table.get_view().horizontalHeader().ResizeMode.ResizeToContents)
        root.addWidget(self._table)

    def _on_row_select(self, row_data: list):
        rec_id = row_data[7]
        rec = self._records.get(rec_id)
        if rec:
            _activity_detail(rec, self)
