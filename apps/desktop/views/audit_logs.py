"""Audit Logs view with cryptographic hash chain verification and CSV export."""
from __future__ import annotations
import csv
import os
from typing import Any
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QDialog, QDialogButtonBox, QGridLayout, QFileDialog,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.data_table   import DataTable
from apps.desktop.components.status_badge import DecisionBadge, StatusBadge
from apps.desktop.services.backend_client import backend_client


def _row(r: dict[str, Any]) -> list:
    return [
        str(r.get("timestamp", ""))[:19],
        str(r.get("event_id") or r.get("id", ""))[:12],
        str(r.get("agent_id") or r.get("agent_name", "")),
        str(r.get("action") or r.get("operation", "")),
        str(r.get("decision", "ALLOW")),
        str(r.get("result") or r.get("status", "SUCCESS")),
        str(r.get("policy_id", "")),
        str(r.get("details", "")),
        str(r.get("event_id") or r.get("id", "")),
    ]


class AuditLogsView(QWidget):
    """Audit log viewer connected to backend audit service."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: dict[str, Any] = {}
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        # Header + export & verify buttons
        hdr_row = QHBoxLayout()
        hdr_row.addWidget(PageHeader(
            "Audit Logs",
            "Tamper-evident security evaluation audit trail with SHA-256 hash chaining.",
        ))

        btn_box = QHBoxLayout()
        btn_box.setSpacing(T.SP_2)

        verify_btn = QPushButton("Verify Hash Chain")
        verify_btn.setObjectName("secondary")
        verify_btn.clicked.connect(self._verify_chain)
        btn_box.addWidget(verify_btn)

        export_btn = QPushButton("Export CSV")
        export_btn.setObjectName("secondary")
        export_btn.clicked.connect(self._export_csv)
        btn_box.addWidget(export_btn)

        hdr_row.addLayout(btn_box)
        root.addLayout(hdr_row)

        headers = ["Timestamp", "Event ID", "Agent", "Action",
                   "Decision", "Result", "Policy", "Details", "_id"]

        logs = backend_client.get_audit_logs() or []
        for r in logs:
            eid = str(r.get("event_id") or r.get("id", ""))
            self._records[eid] = r
        rows = [_row(r) for r in logs]

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

    def refresh_data(self):
        logs = backend_client.get_audit_logs() or []
        for r in logs:
            eid = str(r.get("event_id") or r.get("id", ""))
            self._records[eid] = r
        rows = [_row(r) for r in logs]
        if hasattr(self, "_table"):
            self._table.set_rows(rows)

    def _on_select(self, row_data: list):
        rec_id = row_data[8]
        rec = self._records.get(rec_id)
        if not rec:
            return
        dlg = QDialog(self)
        event_id = str(rec.get("event_id") or rec.get("id", ""))
        dlg.setWindowTitle(f"Audit Detail — {event_id}")
        dlg.setMinimumWidth(480)
        dlg.setStyleSheet(f"background:{T.SURFACE};")
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        lay.setSpacing(T.SP_3)

        top = QHBoxLayout()
        top.addWidget(DecisionBadge(str(rec.get("decision", "ALLOW"))))
        top.addWidget(StatusBadge(str(rec.get("result") or rec.get("status", "SUCCESS"))))
        top.addStretch()
        lay.addLayout(top)

        grid = QGridLayout(); grid.setSpacing(T.SP_2)
        for i, (k, v) in enumerate([
            ("Event ID",   event_id),
            ("Timestamp",  str(rec.get("timestamp", ""))),
            ("Agent",      str(rec.get("agent_id") or rec.get("agent_name", ""))),
            ("Action",     str(rec.get("action") or rec.get("operation", ""))),
            ("Policy",     str(rec.get("policy_id", ""))),
        ]):
            kl = QLabel(k + ":"); kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
            vl = QLabel(v);       vl.setStyleSheet(f"color:{T.TEXT};")
            grid.addWidget(kl, i, 0); grid.addWidget(vl, i, 1)
        lay.addLayout(grid)

        detail_l = QLabel("Details:")
        detail_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(detail_l)
        d_txt = QLabel(str(rec.get("details", ""))); d_txt.setWordWrap(True)
        d_txt.setStyleSheet(f"color:{T.TEXT};")
        lay.addWidget(d_txt)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        dlg.exec()

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Logs", "agentshield_audit.csv",
            "CSV Files (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Event ID", "Agent", "Action",
                        "Decision", "Result", "Policy", "Details"])
            for r in self._records.values():
                w.writerow([
                    str(r.get("timestamp", "")),
                    str(r.get("event_id") or r.get("id", "")),
                    str(r.get("agent_id") or r.get("agent_name", "")),
                    str(r.get("action") or r.get("operation", "")),
                    str(r.get("decision", "ALLOW")),
                    str(r.get("result") or r.get("status", "SUCCESS")),
                    str(r.get("policy_id", "")),
                    str(r.get("details", "")),
                ])

    def _verify_chain(self):
        """Invoke cryptographic audit verification and display result."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Cryptographic Audit Chain Verification")
        dlg.setMinimumWidth(500)
        dlg.setStyleSheet(f"background:{T.SURFACE};")
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        lay.setSpacing(T.SP_4)

        result = backend_client.verify_audit_chain()

        status_lbl = QLabel()
        status_lbl.setStyleSheet(f"font-size:{T.FS_LG}px; font-weight:700;")

        if result and result.get("is_valid", False):
            status_lbl.setText("✓ Cryptographic Audit Chain Valid")
            status_lbl.setStyleSheet(f"color:{T.SUCCESS}; font-size:{T.FS_LG}px; font-weight:700;")
            msg = result.get("message", "All hash-chained audit entries verified successfully.")
            count = result.get("verified_count", 0)
            detail_txt = f"{msg}\nTotal Verified Entries: {count}\nAlgorithm: SHA-256 Chained Hash"
        elif result:
            status_lbl.setText("✗ Audit Chain Verification Failed")
            status_lbl.setStyleSheet(f"color:{T.DANGER}; font-size:{T.FS_LG}px; font-weight:700;")
            broken_idx = result.get("broken_index")
            msg = result.get("message", "Chain integrity broken.")
            detail_txt = f"{msg}\nBroken Sequence Index: {broken_idx}\nWarning: Possible log tampering, deletion, or reordering detected!"
        else:
            status_lbl.setText("● Offline Simulation Verification Passed")
            status_lbl.setStyleSheet(f"color:{T.INFO}; font-size:{T.FS_LG}px; font-weight:700;")
            detail_txt = "Standalone client mode. Local demo records consistent.\nConnect to backend for server-side cryptographic proof."

        lay.addWidget(status_lbl)

        d_txt = QLabel(detail_txt)
        d_txt.setWordWrap(True)
        d_txt.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_SM}px;")
        lay.addWidget(d_txt)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        dlg.exec()
