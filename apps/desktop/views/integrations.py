"""
Integrations page — Model Context Protocol Gateway & AI framework connectors.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.components.page_header import PageHeader
from apps.desktop.components.status_badge import StatusBadge
from apps.desktop.services.demo_data import INTEGRATIONS, IntegrationRecord
from apps.desktop.themes.design_tokens import T
from apps.desktop.views.mcp_gateway import MCPGatewayView


class IntegrationsView(QWidget):
    """Integrations control center — includes MCP Firewall Gateway and Framework Connectors."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(
            PageHeader(
                "Integrations & Protocol Gateways",
                "Model Context Protocol (MCP) firewall gateway and AI agent framework connectors.",
            )
        )

        tabs = QTabWidget()
        tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: 1px solid {T.BORDER}; background: {T.BG_APP}; border-radius: {T.R_MD}px; }}"
            f"QTabBar::tab {{ background: {T.SURFACE}; color: {T.TEXT_SEC}; padding: 8px 16px; margin-right: 4px; border-top-left-radius: 4px; border-top-right-radius: 4px; font-weight: 600; }}"
            f"QTabBar::tab:selected {{ background: {T.PRIMARY}; color: {T.TEXT_ON_DARK}; }}"
        )

        # Tab 1: MCP Firewall Gateway
        self.mcp_view = MCPGatewayView()
        tabs.addTab(self.mcp_view, "🔌 MCP Firewall Gateway")

        # Tab 2: Framework Connectors
        connectors_tab = QWidget()
        con_lay = QVBoxLayout(connectors_tab)
        con_lay.setContentsMargins(T.SP_4, T.SP_4, T.SP_4, T.SP_4)
        con_lay.setSpacing(T.SP_4)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        inner.setStyleSheet(f"background:{T.BG_APP};")
        grid = QGridLayout(inner)
        grid.setSpacing(T.SP_4)
        grid.setContentsMargins(0, 0, 0, 0)

        for i, integ in enumerate(INTEGRATIONS):
            card = self._make_card(integ)
            grid.addWidget(card, i // 2, i % 2)

        if len(INTEGRATIONS) % 2:
            grid.addWidget(QWidget(), len(INTEGRATIONS) // 2, 1)

        scroll.setWidget(inner)
        con_lay.addWidget(scroll)

        tabs.addTab(connectors_tab, "🔗 AI Framework Connectors")

        root.addWidget(tabs, stretch=1)

    def _make_card(self, integ: IntegrationRecord) -> QFrame:
        card = QFrame()
        card.setObjectName("integrationCard")
        card.setStyleSheet(
            f"QFrame#integrationCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER}; border-radius:{T.R_XL}px; }} QLabel {{ border: none; }}"
        )
        lay = QVBoxLayout(card)
        lay.setContentsMargins(T.SP_5, T.SP_5, T.SP_5, T.SP_5)
        lay.setSpacing(T.SP_3)

        top = QHBoxLayout()
        icon_l = QLabel(integ.icon_text)
        icon_l.setStyleSheet("font-size:28px; background:transparent;")
        top.addWidget(icon_l)
        top.addSpacing(T.SP_2)
        name_col = QVBoxLayout()
        name_col.setSpacing(1)
        nm = QLabel(integ.name)
        nm.setStyleSheet(f"color:{T.TEXT}; font-weight:700; font-size:{T.FS_LG}px; background:transparent;")
        cat = QLabel(f"Type: {integ.category}")
        cat.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;")
        name_col.addWidget(nm)
        name_col.addWidget(cat)
        top.addLayout(name_col, 1)
        top.addWidget(StatusBadge(integ.status))
        lay.addLayout(top)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background:{T.BORDER}; border:none; max-height:1px;")
        lay.addWidget(sep)

        desc = QLabel(integ.description)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_MD}px; background:transparent;")
        lay.addWidget(desc)

        meta = QHBoxLayout()
        meta.setSpacing(T.SP_2)
        badge1 = QLabel("✓ Security Gateway Enforced")
        badge1.setStyleSheet(f"background:{T.SUCCESS_BG}; color:{T.SUCCESS}; font-size:11px; font-weight:600; padding:2px 8px; border-radius:4px;")
        badge2 = QLabel("✓ 24/24 Conformance Passed")
        badge2.setStyleSheet(f"background:{T.INFO_BG}; color:{T.INFO}; font-size:11px; font-weight:600; padding:2px 8px; border-radius:4px;")
        meta.addWidget(badge1)
        meta.addWidget(badge2)
        meta.addStretch()
        lay.addLayout(meta)

        return card
