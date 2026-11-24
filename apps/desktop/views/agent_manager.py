"""Agent Manager view — Phase 2 demo data only."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QScrollArea, QDialog, QDialogButtonBox, QGridLayout, QLineEdit, QComboBox,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.status_badge import StatusBadge, RiskBadge
from apps.desktop.components.data_table   import DataTable
from apps.desktop.components.empty_state  import EmptyState
from apps.desktop.services.demo_data      import AGENTS, AgentRecord


def _detail_dialog(agent: AgentRecord, parent) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(f"Agent Details — {agent.name}")
    dlg.setMinimumWidth(480)
    dlg.setStyleSheet(f"background:{T.SURFACE};")

    lay = QVBoxLayout(dlg)
    lay.setSpacing(T.SP_4)
    lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)

    # Header row
    hdr = QHBoxLayout()
    name_lbl = QLabel(agent.name)
    name_lbl.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_XL}px; font-weight:700;")
    hdr.addWidget(name_lbl)
    hdr.addStretch()
    hdr.addWidget(StatusBadge(agent.status))
    lay.addLayout(hdr)

    # Framework
    fw_lbl = QLabel(f"Framework: {agent.framework}")
    fw_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_MD}px;")
    lay.addWidget(fw_lbl)

    sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color:{T.BORDER};")
    lay.addWidget(sep)

    # Details grid
    grid = QGridLayout()
    grid.setSpacing(T.SP_2)
    items = [
        ("Agent ID",         agent.agent_id),
        ("Status",           agent.status),
        ("Risk Status",      agent.risk_status),
        ("Last Seen",        agent.last_seen),
        ("Tools Registered", str(agent.tools_registered)),
        ("Total Actions",    str(agent.total_actions)),
        ("Blocked Actions",  str(agent.blocked_actions)),
    ]
    for i, (k, v) in enumerate(items):
        kl = QLabel(k + ":")
        kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        vl = QLabel(v)
        vl.setStyleSheet(f"color:{T.TEXT};")
        grid.addWidget(kl, i, 0)
        grid.addWidget(vl, i, 1)
    lay.addLayout(grid)

    desc = QLabel(agent.description)
    desc.setWordWrap(True)
    desc.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_MD}px; padding:{T.SP_2}px;")
    lay.addWidget(desc)

    btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    btns.rejected.connect(dlg.reject)
    lay.addWidget(btns)
    dlg.exec()


class AgentManagerView(QWidget):
    """Agent inventory — demo data only."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Agent Manager",
            "Registered AI agent connectors and their current status.",
            demo_note="DEMO DATA",
        ))

        # Toolbar
        tb = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search agents…")
        self._search.setMaximumWidth(260)
        self._search.textChanged.connect(self._filter)
        tb.addWidget(self._search)

        self._status_combo = QComboBox()
        self._status_combo.addItems(["All Status", "Active", "Idle", "Disconnected", "Error"])
        self._status_combo.setMaximumWidth(160)
        self._status_combo.currentTextChanged.connect(self._filter)
        tb.addWidget(self._status_combo)
        tb.addStretch()

        count_lbl = QLabel(f"{len(AGENTS)} agents")
        count_lbl.setStyleSheet(f"color:{T.TEXT_MUTED}; font-size:{T.FS_SM}px;")
        tb.addWidget(count_lbl)
        root.addLayout(tb)

        # Agent cards in scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._cards_container = QWidget()
        self._cards_container.setStyleSheet(f"background:{T.BG_APP};")
        self._cards_layout = QVBoxLayout(self._cards_container)
        self._cards_layout.setSpacing(T.SP_3)
        self._cards_layout.setContentsMargins(0, 0, 0, 0)
        self._cards_layout.addStretch()
        scroll.setWidget(self._cards_container)

        self._all_agents = AGENTS[:]
        self._render_agents(self._all_agents)
        root.addWidget(scroll)

    def _make_agent_card(self, agent: AgentRecord) -> QFrame:
        card = QFrame()
        card.setObjectName("agentCard")
        card.setStyleSheet(
            f"QFrame#agentCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_LG}px; }} QLabel {{ border: none; }}"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(T.SP_4, T.SP_3, T.SP_4, T.SP_3)
        lay.setSpacing(T.SP_4)

        # Icon
        icon = QLabel("🤖")
        icon.setStyleSheet("font-size:24px; background:transparent; border:none;")
        icon.setFixedWidth(36)
        lay.addWidget(icon)

        # Main info
        info = QVBoxLayout()
        info.setSpacing(2)
        name_lbl = QLabel(agent.name)
        name_lbl.setStyleSheet(f"color:{T.TEXT}; font-weight:700; font-size:{T.FS_MD}px; background:transparent; border:none;")
        fw_lbl = QLabel(f"{agent.framework}  •  ID: {agent.agent_id}")
        fw_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent; border:none;")
        info.addWidget(name_lbl)
        info.addWidget(fw_lbl)
        lay.addLayout(info, 2)

        # Stats
        for label, val in [
            ("Tools", str(agent.tools_registered)),
            ("Actions", str(agent.total_actions)),
            ("Blocked", str(agent.blocked_actions)),
        ]:
            col = QVBoxLayout(); col.setSpacing(1)
            vl = QLabel(val); vl.setStyleSheet(f"color:{T.TEXT}; font-weight:700; font-size:{T.FS_LG}px; background:transparent; border:none;")
            ll = QLabel(label); ll.setStyleSheet(f"color:{T.TEXT_MUTED}; font-size:{T.FS_XS}px; background:transparent; border:none;")
            col.addWidget(vl, alignment=Qt.AlignmentFlag.AlignCenter)
            col.addWidget(ll, alignment=Qt.AlignmentFlag.AlignCenter)
            lay.addLayout(col)

        lay.addSpacing(T.SP_2)
        lay.addWidget(StatusBadge(agent.status))
        lay.addWidget(RiskBadge(agent.risk_status))

        # Detail button
        detail_btn = QPushButton("Details")
        detail_btn.setObjectName("secondary")
        detail_btn.setFixedWidth(80)
        detail_btn.clicked.connect(lambda _, a=agent: _detail_dialog(a, self))
        lay.addWidget(detail_btn)

        return card

    def _render_agents(self, agents: list[AgentRecord]):
        # Clear existing cards (preserve stretch at end)
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        pos = 0
        for agent in agents:
            card = self._make_agent_card(agent)
            self._cards_layout.insertWidget(pos, card)
            pos += 1

    def _filter(self):
        text   = self._search.text().lower()
        status = self._status_combo.currentText()
        result = [
            a for a in self._all_agents
            if (text in a.name.lower() or text in a.agent_id.lower() or text in a.framework.lower())
            and (status == "All Status" or a.status == status)
        ]
        self._render_agents(result)
