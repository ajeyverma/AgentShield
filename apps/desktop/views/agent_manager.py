"""Agent Manager view — Phase 2 demo data only."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QScrollArea, QDialog, QDialogButtonBox, QGridLayout, QLineEdit, QComboBox,
    QMessageBox,
)
from dataclasses import dataclass
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.status_badge import StatusBadge, RiskBadge
from apps.desktop.components.data_table   import DataTable
from apps.desktop.components.empty_state  import EmptyState
from apps.desktop.services.backend_client import backend_client


@dataclass
class AgentRecord:
    agent_id: str
    name: str
    framework: str
    status: str
    last_seen: str
    tools_registered: int
    risk_status: str
    total_actions: int
    blocked_actions: int
    description: str = ""


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


class RegisterAgentDialog(QDialog):
    """Dialog to register a new AI Agent connector with AgentShield."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register New AI Agent")
        self.setMinimumWidth(440)
        self.setStyleSheet(f"background:{T.SURFACE};")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
        lay.setSpacing(T.SP_4)

        title_l = QLabel("Register AI Agent Connector")
        title_l.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_LG}px; font-weight:700;")
        lay.addWidget(title_l)

        sub_l = QLabel("Connect an autonomous agent to enforce runtime firewall policies and threat scanning.")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px;")
        sub_l.setWordWrap(True)
        lay.addWidget(sub_l)

        form = QGridLayout()
        form.setSpacing(T.SP_3)

        form.addWidget(QLabel("Agent Name:"), 0, 0)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. ResearchAgent-Prod")
        form.addWidget(self.name_edit, 0, 1)

        form.addWidget(QLabel("Framework:"), 1, 0)
        self.framework_combo = QComboBox()
        self.framework_combo.addItems(["openai", "claude", "langgraph", "crewai", "google_adk", "custom"])
        form.addWidget(self.framework_combo, 1, 1)

        form.addWidget(QLabel("Description:"), 2, 0)
        self.desc_edit = QLineEdit()
        self.desc_edit.setPlaceholderText("Optional description of agent duties...")
        form.addWidget(self.desc_edit, 2, 1)

        lay.addLayout(form)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Register Agent")
        btns.accepted.connect(self._register)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _register(self):
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Validation Error", "Agent name is required.")
            return

        framework = self.framework_combo.currentText()
        desc = self.desc_edit.text().strip() or None

        res = backend_client.create_agent(name=name, framework=framework, description=desc)
        if res:
            agent_id = res.get("id", "")
            raw_cred = res.get("raw_credential", "")
            msg = (
                f"Agent '{name}' has been successfully registered!\n\n"
                f"Agent ID:\n{agent_id}\n\n"
                f"Security Credential (Token):\n{raw_cred}\n\n"
                "IMPORTANT: Copy and store this credential token safely. It will not be shown again."
            )
            QMessageBox.information(self, "Agent Registered", msg)
            self.accept()
        else:
            QMessageBox.critical(
                self,
                "Registration Failed",
                "Could not register agent. Ensure the AgentShield API backend is running and reachable on http://127.0.0.1:8000."
            )


class AgentManagerView(QWidget):
    """Agent inventory — live backend integration with clean empty state."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_agents: list[AgentRecord] = []
        self._build()
        self.refresh_data()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Agent Manager",
            "Registered AI agent connectors and their current status.",
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

        # Add Agent button
        add_btn = QPushButton("+ Register Agent")
        add_btn.setObjectName("primary")
        add_btn.setStyleSheet(
            f"background-color:{T.PRIMARY}; color:{T.TEXT_ON_PRIMARY}; border:none; padding:5px 12px; font-weight:600; border-radius:{T.R_SM}px;"
        )
        add_btn.clicked.connect(self._open_add_agent_dialog)
        tb.addWidget(add_btn)

        refresh_btn = QPushButton("⟳ Refresh")
        refresh_btn.setObjectName("secondary")
        refresh_btn.setStyleSheet(
            f"background-color:{T.SURFACE}; color:{T.TEXT}; border:1px solid {T.BORDER}; padding:5px 10px; border-radius:{T.R_SM}px;"
        )
        refresh_btn.clicked.connect(self.refresh_data)
        tb.addWidget(refresh_btn)

        tb.addStretch()

        self._count_lbl = QLabel("0 agents")
        self._count_lbl.setStyleSheet(f"color:{T.TEXT_MUTED}; font-size:{T.FS_SM}px;")
        tb.addWidget(self._count_lbl)
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

        root.addWidget(scroll)

    def _open_add_agent_dialog(self):
        dlg = RegisterAgentDialog(self)
        if dlg.exec():
            self.refresh_data()

    def refresh_data(self):
        """Fetch real registered agents from backend; do not use fake demo data."""
        real_agents = backend_client.get_agents()
        if real_agents:
            self._all_agents = [
                AgentRecord(
                    agent_id=str(a.get("id", "")),
                    name=a.get("agent_name") or a.get("name", "Unnamed Agent"),
                    framework=a.get("framework", "Agent SDK"),
                    status=str(a.get("status", "Active")).capitalize(),
                    last_seen=str(a.get("last_seen_at") or a.get("last_active_at") or a.get("created_at") or "Recently")[:19],
                    tools_registered=len(a.get("tools", [])),
                    risk_status="Normal",
                    total_actions=a.get("total_actions", 0),
                    blocked_actions=a.get("blocked_actions", 0),
                    description=a.get("description", ""),
                )
                for a in real_agents
            ]
        else:
            self._all_agents = []

        self._count_lbl.setText(f"{len(self._all_agents)} agents")
        self._render_agents(self._all_agents)

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

        if not agents:
            empty = EmptyState("🤖", "No autonomous agents registered yet. Register an agent via API or CLI to see it here.")
            self._cards_layout.insertWidget(0, empty)
            return

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
        self._count_lbl.setText(f"{len(result)} agents")
        self._render_agents(result)
