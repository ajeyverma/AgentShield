"""Audit Logs view — Phase 2 demo data with CSV export."""
from __future__ import annotations
import csv
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QDialog, QDialogButtonBox, QGridLayout, QFileDialog,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.data_table   import DataTable
from apps.desktop.components.status_badge import DecisionBadge, StatusBadge
from apps.desktop.services.demo_data      import AUDIT_LOGS, AuditRecord


def _row(r: AuditRecord) -> list:
    return [r.timestamp, r.event_id, r.agent_name, r.action,
            r.decision, r.result, r.policy_id, r.details, r.event_id]


class AuditLogsView(QWidget):
    """Audit log viewer — demo data only."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records = {r.event_id: r for r in AUDIT_LOGS}
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        # Header + export button
        hdr_row = QHBoxLayout()
        hdr_row.addWidget(PageHeader(
            "Audit Logs",
            "Security evaluation audit trail.",
            demo_note="DEMO DATA — Not an immutable production audit log",
        ))
        export_btn = QPushButton("Export CSV")
        export_btn.setObjectName("secondary")
        export_btn.clicked.connect(self._export_csv)
        hdr_row.addWidget(export_btn, alignment=__import__("PySide6.QtCore", fromlist=["Qt"]).Qt.AlignmentFlag.AlignRight)
        root.addLayout(hdr_row)

        headers = ["Timestamp", "Event ID", "Agent", "Action",
                   "Decision", "Result", "Policy", "Details", "_id"]
        rows = [_row(r) for r in AUDIT_LOGS]

        self._table = DataTable(
            headers, rows,
            filter_col=4,
            filter_options=["All", "ALLOW", "BLOCK", "ASK_HUMAN"],
            on_select=self._on_select,
        )
        # Hide details and ID columns from view
        for col in (7, 8):
            self._table.get_view().setColumnHidden(col, True)
        root.addWidget(self._table)

    def _on_select(self, row_data: list):
        rec_id = row_data[8]
        rec = self._records.get(rec_id)
        if not rec:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Audit Detail — {rec.event_id}")
        dlg.setMinimumWidth(480)
        dlg.setStyleSheet(f"background:{T.SURFACE};")
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        lay.setSpacing(T.SP_3)

        top = QHBoxLayout()
        top.addWidget(DecisionBadge(rec.decision))
        top.addWidget(StatusBadge(rec.result))
        top.addStretch()
        lay.addLayout(top)

        grid = QGridLayout(); grid.setSpacing(T.SP_2)
        for i, (k, v) in enumerate([
            ("Event ID",   rec.event_id),
            ("Timestamp",  rec.timestamp),
            ("Agent",      rec.agent_name),
            ("Action",     rec.action),
            ("Policy",     rec.policy_id),
        ]):
            kl = QLabel(k + ":"); kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
            vl = QLabel(v);       vl.setStyleSheet(f"color:{T.TEXT};")
            grid.addWidget(kl, i, 0); grid.addWidget(vl, i, 1)
        lay.addLayout(grid)

        detail_l = QLabel("Details:")
        detail_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(detail_l)
        d_txt = QLabel(rec.details); d_txt.setWordWrap(True)
        d_txt.setStyleSheet(f"color:{T.TEXT};")
        lay.addWidget(d_txt)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        dlg.exec()

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Logs", "agentshield_audit_demo.csv",
            "CSV Files (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Event ID", "Agent", "Action",
                        "Decision", "Result", "Policy", "Details"])
            for r in AUDIT_LOGS:
                w.writerow([r.timestamp, r.event_id, r.agent_name, r.action,
                            r.decision, r.result, r.policy_id, r.details])
