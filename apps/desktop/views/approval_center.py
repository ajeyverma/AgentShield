"""Approval Center view — Phase 2 demo data, local state only."""
from __future__ import annotations
from copy import deepcopy
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QScrollArea, QDialog, QDialogButtonBox, QGridLayout, QTextEdit,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.stat_card    import StatCard
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.status_badge import RiskBadge, StatusBadge
from apps.desktop.services.demo_data      import APPROVALS, ApprovalRecord
import json


def _approval_detail(rec: ApprovalRecord, parent, on_decision=None) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(f"Approval Request — {rec.request_id}")
    dlg.setMinimumWidth(540)
    dlg.setStyleSheet(f"background:{T.SURFACE};")
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
    lay.setSpacing(T.SP_4)

    # Header
    top = QHBoxLayout()
    name_l = QLabel(rec.tool_name + " → " + rec.operation)
    name_l.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_XL}px; font-weight:700;")
    top.addWidget(name_l); top.addStretch()
    top.addWidget(RiskBadge(rec.risk_level))
    top.addWidget(StatusBadge(rec.status))
    lay.addLayout(top)

    sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color:{T.BORDER};"); lay.addWidget(sep)

    grid = QGridLayout(); grid.setSpacing(T.SP_2)
    for i, (k, v) in enumerate([
        ("Request ID",   rec.request_id),
        ("Agent",        rec.agent_name),
        ("Requested At", rec.requested_at),
    ]):
        kl = QLabel(k + ":"); kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        vl = QLabel(v);       vl.setStyleSheet(f"color:{T.TEXT};")
        grid.addWidget(kl, i, 0); grid.addWidget(vl, i, 1)
    lay.addLayout(grid)

    desc_l = QLabel(rec.description)
    desc_l.setWordWrap(True)
    desc_l.setStyleSheet(f"color:{T.TEXT};")
    lay.addWidget(desc_l)

    # Arguments
    lay.addWidget(_section("Arguments (sanitised):"))
    args_box = QTextEdit()
    args_box.setReadOnly(True)
    args_box.setPlainText(json.dumps(rec.arguments, indent=2))
    args_box.setMaximumHeight(80)
    args_box.setStyleSheet(
        f"background:{T.SURFACE_ALT}; border:1px solid {T.BORDER}; font-family:monospace; font-size:{T.FS_SM}px;"
    )
    lay.addWidget(args_box)

    # Risk explanation
    lay.addWidget(_section("Risk Explanation:"))
    risk_lbl = QLabel(rec.risk_explanation)
    risk_lbl.setWordWrap(True)
    risk_lbl.setStyleSheet(
        f"color:{T.TEXT}; background:{T.WARNING_BG}; border:1px solid {T.WARNING};"
        f"border-radius:{T.R_SM}px; padding:{T.SP_3}px;"
    )
    lay.addWidget(risk_lbl)

    # Permissions
    lay.addWidget(_section("Permissions Requested:"))
    perms = QLabel("  •  " + "\n  •  ".join(rec.permissions_requested))
    perms.setStyleSheet(f"color:{T.TEXT}; font-family:monospace; font-size:{T.FS_SM}px;")
    lay.addWidget(perms)

    # Action buttons (only for Pending)
    if rec.status == "Pending" and on_decision:
        btn_row = QHBoxLayout()
        approve_btn = QPushButton("✓  Approve")
        approve_btn.setObjectName("success")
        approve_btn.clicked.connect(lambda: (on_decision("Approved"), dlg.accept()))
        reject_btn = QPushButton("✗  Reject")
        reject_btn.setObjectName("danger")
        reject_btn.clicked.connect(lambda: (on_decision("Rejected"), dlg.accept()))
        btn_row.addWidget(approve_btn); btn_row.addWidget(reject_btn); btn_row.addStretch()
        lay.addLayout(btn_row)

        note = QLabel(
            "⚠ Demo only: These buttons update local UI state only.\n"
            "No real tool execution is authorized by this action."
        )
        note.setStyleSheet(
            f"color:{T.WARNING}; background:{T.WARNING_BG}; padding:{T.SP_2}px;"
            f"border-radius:{T.R_SM}px; font-size:{T.FS_SM}px;"
        )
        note.setWordWrap(True)
        lay.addWidget(note)
    else:
        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.rejected.connect(dlg.reject)
        lay.addWidget(close_btn)

    dlg.exec()


def _section(text: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
    return l


class ApprovalCenterView(QWidget):
    """Human approval interface — local demo state only."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records = deepcopy(APPROVALS)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Approval Center",
            "Human-in-the-loop approval requests from AI agents.",
            demo_note="DEMO — UI prototype only. No real tool execution.",
        ))

        # Stat cards
        pending  = sum(1 for r in self._records if r.status == "Pending")
        approved = sum(1 for r in self._records if r.status == "Approved")
        rejected = sum(1 for r in self._records if r.status == "Rejected")

        cards_row = QHBoxLayout(); cards_row.setSpacing(T.SP_4)
        self._pending_card  = StatCard("Pending",  str(pending),  accent_color=T.WARNING)
        self._approved_card = StatCard("Approved", str(approved), accent_color=T.SUCCESS)
        self._rejected_card = StatCard("Rejected", str(rejected), accent_color=T.DANGER)
        for c in (self._pending_card, self._approved_card, self._rejected_card):
            cards_row.addWidget(c)
        cards_row.addStretch()
        root.addLayout(cards_row)

        # List
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._list_container = QWidget()
        self._list_container.setStyleSheet(f"background:{T.BG_APP};")
        self._list_layout = QVBoxLayout(self._list_container)
        self._list_layout.setSpacing(T.SP_3)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._render_all()
        self._list_layout.addStretch()
        scroll.setWidget(self._list_container)
        root.addWidget(scroll)

    def _render_all(self):
        while self._list_layout.count() > 1:
            item = self._list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for i, rec in enumerate(self._records):
            self._list_layout.insertWidget(i, self._make_card(rec))
        self._update_counters()

    def _make_card(self, rec: ApprovalRecord) -> QFrame:
        BORDER = {
            "Pending":  T.WARNING,
            "Approved": T.SUCCESS,
            "Rejected": T.DANGER,
        }.get(rec.status, T.BORDER)

        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-left:4px solid {BORDER}; border-radius:{T.R_LG}px; }}"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(T.SP_4, T.SP_3, T.SP_4, T.SP_3)
        lay.setSpacing(T.SP_4)

        left = QVBoxLayout(); left.setSpacing(2)
        name_l = QLabel(f"{rec.tool_name} → {rec.operation}")
        name_l.setStyleSheet(f"color:{T.TEXT}; font-weight:700; background:transparent;")
        sub_l = QLabel(f"Agent: {rec.agent_name}  •  Requested: {rec.requested_at[11:16]}")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;")
        left.addWidget(name_l); left.addWidget(sub_l)
        lay.addLayout(left, 2)

        lay.addWidget(RiskBadge(rec.risk_level))
        lay.addWidget(StatusBadge(rec.status))

        view_btn = QPushButton("Review")
        view_btn.setObjectName("secondary")
        view_btn.setFixedWidth(80)
        view_btn.clicked.connect(lambda _, r=rec: _approval_detail(
            r, self,
            on_decision=lambda d, _r=r: self._apply_decision(_r, d),
        ))
        lay.addWidget(view_btn)
        return card

    def _apply_decision(self, rec: ApprovalRecord, decision: str):
        rec.status = decision
        self._render_all()

    def _update_counters(self):
        self._pending_card.set_value(str(sum(1 for r in self._records if r.status == "Pending")))
        self._approved_card.set_value(str(sum(1 for r in self._records if r.status == "Approved")))
        self._rejected_card.set_value(str(sum(1 for r in self._records if r.status == "Rejected")))
