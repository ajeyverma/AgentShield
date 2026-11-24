"""
AgentShield AI — Approval Center Desktop View (Phase 10).

Provides human-in-the-loop approval management with backend synchronization,
argument inspection, threat finding breakdown, and role-based approval controls.
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.components.page_header import PageHeader
from apps.desktop.components.stat_card import StatCard
from apps.desktop.components.status_badge import RiskBadge, StatusBadge
from apps.desktop.components.empty_state import EmptyState
from apps.desktop.services.backend_client import backend_client
from apps.desktop.themes.design_tokens import T

logger = logging.getLogger("agentshield.desktop.approval_center")


def _section(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
    return lbl


class ApprovalDetailDialog(QDialog):
    """Detailed dialog for inspecting and deciding upon an approval request."""

    def __init__(self, data: dict[str, Any], parent=None, on_decision=None):
        super().__init__(parent)
        self.data = data
        self.on_decision = on_decision
        self._build_ui()

    def _build_ui(self):
        self.setWindowTitle(f"Approval Request — {self.data.get('request_id', self.data.get('id', ''))}")
        self.setMinimumWidth(580)
        self.setStyleSheet(f"background:{T.SURFACE};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        layout.setSpacing(T.SP_4)

        # Header: Tool / Operation + Badges
        top = QHBoxLayout()
        tool_name = self.data.get("tool_name", "Unknown Tool")
        operation = self.data.get("operation", "action")
        name_l = QLabel(f"{tool_name} → {operation}")
        name_l.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_XL}px; font-weight:700;")
        top.addWidget(name_l)
        top.addStretch()

        risk_level = self.data.get("risk_level", "MEDIUM")
        status_val = self.data.get("status", "pending").capitalize()
        top.addWidget(RiskBadge(risk_level))
        top.addWidget(StatusBadge(status_val))
        layout.addLayout(top)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color:{T.BORDER};")
        layout.addWidget(sep)

        # Metadata Grid
        grid = QGridLayout()
        grid.setSpacing(T.SP_2)
        items = [
            ("Request ID", str(self.data.get("request_id", "-"))),
            ("Agent ID", str(self.data.get("agent_id", "-"))),
            ("Risk Score", f"{self.data.get('risk_score', 0):.0f}/100" if self.data.get("risk_score") is not None else "N/A"),
            ("Resource", str(self.data.get("resource", "-"))),
            ("Created At", str(self.data.get("created_at", "-"))[:19]),
            ("Expires At", str(self.data.get("expires_at", "No timeout"))[:19] if self.data.get("expires_at") else "No timeout"),
        ]
        for idx, (label, val) in enumerate(items):
            k_lbl = QLabel(f"{label}:")
            k_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
            v_lbl = QLabel(val)
            v_lbl.setStyleSheet(f"color:{T.TEXT};")
            grid.addWidget(k_lbl, idx // 2, (idx % 2) * 2)
            grid.addWidget(v_lbl, idx // 2, (idx % 2) * 2 + 1)
        layout.addLayout(grid)

        # Description
        desc_text = self.data.get("description", "")
        if desc_text:
            desc_l = QLabel(desc_text)
            desc_l.setWordWrap(True)
            desc_l.setStyleSheet(f"color:{T.TEXT};")
            layout.addWidget(desc_l)

        # Sanitized Arguments Box
        layout.addWidget(_section("Execution Arguments (Secrets Redacted):"))
        args_data = self.data.get("sanitized_arguments") or self.data.get("arguments") or {}
        if isinstance(args_data, str):
            try:
                args_data = json.loads(args_data)
            except Exception:
                pass
        args_box = QTextEdit()
        args_box.setReadOnly(True)
        args_box.setPlainText(json.dumps(args_data, indent=2, default=str))
        args_box.setMaximumHeight(90)
        args_box.setStyleSheet(
            f"background:{T.SURFACE_ALT}; border:none; border-radius:{T.R_SM}px; font-family:monospace; font-size:{T.FS_SM}px; padding:6px 10px;"
        )
        layout.addWidget(args_box)

        # Threat findings breakdown
        threats = self.data.get("threat_findings", [])
        if threats:
            layout.addWidget(_section(f"Threat Detection Findings ({len(threats)}):"))
            threats_box = QTextEdit()
            threats_box.setReadOnly(True)
            lines = []
            for t in threats:
                sev = t.get("severity", "MEDIUM")
                t_type = t.get("threat_type", "Threat")
                desc = t.get("description", "")
                lines.append(f"• [{sev}] {t_type}: {desc}")
            threats_box.setPlainText("\n".join(lines))
            threats_box.setMaximumHeight(80)
            threats_box.setStyleSheet(
                f"background:{T.WARNING_BG}; border:none; border-radius:{T.R_SM}px; font-size:{T.FS_SM}px; color:{T.TEXT}; padding:6px 10px;"
            )
            layout.addWidget(threats_box)

        # Review history / info if resolved
        if status_val.lower() in ("approved", "rejected", "cancelled"):
            rev_by = self.data.get("reviewed_by") or "Admin"
            rev_at = str(self.data.get("reviewed_at", ""))[:19]
            rev_comment = self.data.get("review_comment") or self.data.get("rejection_reason") or "-"
            rev_box = QLabel(f"Resolved by {rev_by} at {rev_at}\nNote: {rev_comment}")
            rev_box.setStyleSheet(
                f"background:{T.SURFACE_ALT}; border:none; padding:{T.SP_2}px; border-radius:{T.R_SM}px; font-size:{T.FS_SM}px; color:{T.TEXT};"
            )
            layout.addWidget(rev_box)

        # Action Buttons (only for pending)
        if status_val.lower() == "pending" and self.on_decision:
            btn_row = QHBoxLayout()
            approve_btn = QPushButton("✓  Approve Request")
            approve_btn.setObjectName("success")
            approve_btn.clicked.connect(self._handle_approve)

            reject_btn = QPushButton("✗  Reject Request")
            reject_btn.setObjectName("danger")
            reject_btn.clicked.connect(self._handle_reject)

            btn_row.addWidget(approve_btn)
            btn_row.addWidget(reject_btn)
            btn_row.addStretch()
            layout.addLayout(btn_row)
        else:
            close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            close_btn.rejected.connect(self.reject)
            layout.addWidget(close_btn)

    def _handle_approve(self):
        comment, ok = QInputDialog.getText(
            self,
            "Approval Comment",
            "Optional approval note/justification:",
        )
        if ok and self.on_decision:
            self.on_decision("approve", comment.strip() if comment else None)
            self.accept()

    def _handle_reject(self):
        reason, ok = QInputDialog.getText(
            self,
            "Rejection Reason",
            "Enter reason for rejecting this execution request (required):",
        )
        if ok and reason and reason.strip():
            if self.on_decision:
                self.on_decision("reject", reason.strip())
                self.accept()
        elif ok and (not reason or not reason.strip()):
            QMessageBox.warning(self, "Validation Error", "A rejection reason is required.")


class ApprovalCenterView(QWidget):
    """Human approval management interface with backend synchronization."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: list[dict[str, Any]] = []
        self._build_ui()
        self.refresh_data()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Approval Center",
            "Human-in-the-loop authorization gateway for protected agent operations.",
        ))

        # Stat cards row
        self._pending_card = StatCard("Pending", "0", accent_color=T.WARNING)
        self._approved_card = StatCard("Approved", "0", accent_color=T.SUCCESS)
        self._rejected_card = StatCard("Rejected", "0", accent_color=T.DANGER)

        cards_row = QHBoxLayout()
        cards_row.setSpacing(T.SP_4)
        cards_row.addWidget(self._pending_card)
        cards_row.addWidget(self._approved_card)
        cards_row.addWidget(self._rejected_card)
        cards_row.addStretch()
        root.addLayout(cards_row)

        # Filters toolbar
        tools_row = QHBoxLayout()
        tools_row.setSpacing(T.SP_3)

        self._status_filter = QComboBox()
        self._status_filter.addItems(["All Statuses", "Pending", "Approved", "Rejected", "Expired"])
        self._status_filter.currentTextChanged.connect(self._apply_filters)
        tools_row.addWidget(QLabel("Filter:"))
        tools_row.addWidget(self._status_filter)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search tool, action, or description...")
        self._search_input.textChanged.connect(self._apply_filters)
        tools_row.addWidget(self._search_input, 1)

        refresh_btn = QPushButton("⟳ Refresh")
        refresh_btn.setObjectName("secondary")
        refresh_btn.clicked.connect(self.refresh_data)
        tools_row.addWidget(refresh_btn)

        root.addLayout(tools_row)

        # Scrollable list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._list_container = QWidget()
        self._list_container.setStyleSheet(f"background:{T.BG_APP};")
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setSpacing(T.SP_3)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.addStretch()
        scroll.setWidget(self._list_container)
        root.addWidget(scroll, stretch=1)

    def refresh_data(self):
        """Fetch real approval requests from backend."""
        backend_items = backend_client.get_approvals()
        if backend_items is not None:
            self._records = backend_items
        else:
            self._records = []
        self._apply_filters()

    def _apply_filters(self):
        st_filter = self._status_filter.currentText().lower()
        search_query = self._search_input.text().strip().lower()

        filtered = []
        for r in self._records:
            status_match = (st_filter == "all statuses") or (r.get("status", "").lower() == st_filter)
            text_match = (
                not search_query
                or search_query in r.get("tool_name", "").lower()
                or search_query in r.get("operation", "").lower()
                or search_query in r.get("description", "").lower()
            )
            if status_match and text_match:
                filtered.append(r)

        self._render_list(filtered)

    def _render_list(self, records: list[dict[str, Any]]):
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not records:
            empty = EmptyState(
                "📋",
                "No pending or historical approval requests found.",
                "Tool calls requiring human authorization will appear here when an agent triggers an ASK_HUMAN policy.",
            )
            self._list_layout.insertWidget(0, empty)
        else:
            for idx, rec in enumerate(records):
                card = self._make_card(rec)
                self._list_layout.insertWidget(idx, card)

        # Update counter badges
        pending_count = sum(1 for r in self._records if r.get("status", "").lower() == "pending")
        approved_count = sum(1 for r in self._records if r.get("status", "").lower() == "approved")
        rejected_count = sum(1 for r in self._records if r.get("status", "").lower() == "rejected")

        self._pending_card.set_value(str(pending_count))
        self._approved_card.set_value(str(approved_count))
        self._rejected_card.set_value(str(rejected_count))

    def _make_card(self, rec: dict[str, Any]) -> QFrame:
        st = rec.get("status", "pending").capitalize()
        border_col = {
            "Pending": T.WARNING,
            "Approved": T.SUCCESS,
            "Rejected": T.DANGER,
        }.get(st, T.BORDER)

        card = QFrame()
        card.setObjectName("approvalCard")
        card.setStyleSheet(
            f"QFrame#approvalCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-left:4px solid {border_col}; border-radius:{T.R_LG}px; }} QLabel {{ border: none; }}"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(T.SP_4, T.SP_3, T.SP_4, T.SP_3)
        lay.setSpacing(T.SP_4)

        left = QVBoxLayout()
        left.setSpacing(2)
        tool_name = rec.get("tool_name", "Tool")
        op_name = rec.get("operation", "action")
        name_l = QLabel(f"{tool_name} → {op_name}")
        name_l.setStyleSheet(f"color:{T.TEXT}; font-weight:700; background:transparent;")

        agent_val = rec.get("agent_id", "Agent")
        created_val = str(rec.get("created_at", ""))[:16]
        sub_l = QLabel(f"Agent: {agent_val}  •  Requested: {created_val}")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;")
        left.addWidget(name_l)
        left.addWidget(sub_l)
        lay.addLayout(left, 2)

        risk_val = rec.get("risk_level", "MEDIUM")
        lay.addWidget(RiskBadge(risk_val))
        lay.addWidget(StatusBadge(st))

        review_btn = QPushButton("Review")
        review_btn.setObjectName("secondary")
        review_btn.setFixedWidth(80)
        review_btn.clicked.connect(lambda _, r=rec: self._open_detail(r))
        lay.addWidget(review_btn)

        return card

    def _open_detail(self, rec: dict[str, Any]):
        appr_id = rec.get("id") or rec.get("request_id")
        detail_data = backend_client.get_approval_detail(appr_id) if appr_id else None
        if not detail_data:
            detail_data = rec

        dlg = ApprovalDetailDialog(
            detail_data,
            parent=self,
            on_decision=lambda action, note: self._execute_decision(appr_id, action, note),
        )
        dlg.exec()

    def _execute_decision(self, approval_id: str, action: str, note: str | None):
        if action == "approve":
            res = backend_client.approve_request(approval_id, comment=note)
            if res:
                QMessageBox.information(self, "Approved", "Execution request successfully approved and resumed!")
            else:
                QMessageBox.warning(self, "Approval Error", "Failed to approve request via backend.")
        elif action == "reject":
            res = backend_client.reject_request(approval_id, reason=note or "Rejected by human approver")
            if res:
                QMessageBox.information(self, "Rejected", "Execution request rejected.")
            else:
                QMessageBox.warning(self, "Rejection Error", "Failed to reject request via backend.")

        self.refresh_data()
