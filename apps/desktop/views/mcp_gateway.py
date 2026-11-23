"""
AgentShield AI — MCP Gateway Desktop View (Phase 8).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.components.data_table import DataTable
from apps.desktop.components.page_header import PageHeader
from apps.desktop.components.stat_card import StatCard
from apps.desktop.components.status_badge import StatusBadge
from apps.desktop.themes.design_tokens import T


class MCPGatewayView(QWidget):
    """
    Desktop view for managing MCP upstream servers, inspecting discovered tools,
    and monitoring intercepted operations through the protocol firewall.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(
            PageHeader(
                "MCP Firewall Gateway",
                "Model Context Protocol runtime security gateway, tool namespacing, and upstream server mediation.",
            )
        )

        # Stat cards row
        stats_lay = QHBoxLayout()
        stats_lay.setSpacing(T.SP_4)

        self.sc_servers = StatCard("Active MCP Servers", "2", "Configured", "primary")
        self.sc_tools = StatCard("Discovered Tools", "14", "Namespaced", "info")
        self.sc_ops = StatCard("Mediated Calls", "128", "Past 24h", "success")
        self.sc_threats = StatCard("Threats Intercepted", "3", "Blocked / Redacted", "danger")

        stats_lay.addWidget(self.sc_servers)
        stats_lay.addWidget(self.sc_tools)
        stats_lay.addWidget(self.sc_ops)
        stats_lay.addWidget(self.sc_threats)
        root.addLayout(stats_lay)

        # Scroll area for server tables
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        inner = QWidget()
        inner.setStyleSheet(f"background:{T.BG_APP};")
        inner_lay = QVBoxLayout(inner)
        inner_lay.setContentsMargins(0, 0, 0, 0)
        inner_lay.setSpacing(T.SP_5)

        # 1. Registered Upstream Servers
        servers_card = self._make_section_frame("Registered Upstream MCP Servers")
        sc_lay = QVBoxLayout(servers_card)
        sc_lay.setContentsMargins(T.SP_4, T.SP_4, T.SP_4, T.SP_4)

        self.servers_table = DataTable(
            headers=["Server Name", "Transport", "Endpoint / Command", "Trust", "Status", "Last Connected"],
            rows=[
                ["filesystem-mcp", "stdio", "npx -y @modelcontextprotocol/server-filesystem", "Internal", "CONNECTED", "Just now"],
                ["sqlite-mcp", "stdio", "python -m mcp_server_sqlite --db dev.db", "Internal", "CONNECTED", "2 mins ago"],
                ["weather-remote", "streamable_http", "https://api.weather-mcp.cloud/rpc", "Partner", "CONNECTED", "10 mins ago"],
            ],
        )
        sc_lay.addWidget(self.servers_table)
        inner_lay.addWidget(servers_card)

        # 2. Intercepted Protocol Activity Log
        activity_card = self._make_section_frame("Recent MCP Firewall Interceptions")
        act_lay = QVBoxLayout(activity_card)
        act_lay.setContentsMargins(T.SP_4, T.SP_4, T.SP_4, T.SP_4)

        self.activity_table = DataTable(
            headers=["Timestamp", "Server", "Operation", "Target", "Decision", "Status", "Redaction"],
            rows=[
                ["12:30:15", "filesystem-mcp", "tools/call", "filesystem_read_file", "ALLOW", "SUCCESS", "None"],
                ["12:28:42", "weather-remote", "tools/call", "weather_fetch_forecast", "ALLOW", "SUCCESS", "None"],
                ["12:25:10", "filesystem-mcp", "tools/call", "filesystem_write_file", "BLOCK", "BLOCKED", "None"],
                ["12:20:04", "sqlite-mcp", "tools/call", "sqlite_query", "ALLOW", "SUCCESS", "API_KEY Redacted"],
            ],
        )
        act_lay.addWidget(self.activity_table)
        inner_lay.addWidget(activity_card)

        scroll.setWidget(inner)
        root.addWidget(scroll, stretch=1)

    def _make_section_frame(self, title: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background:{T.SURFACE}; border:1px solid {T.BORDER}; border-radius:{T.R_LG}px; }}"
        )
        lbl = QLabel(f"<b>{title}</b>")
        lbl.setStyleSheet(f"color:{T.TEXT_PRIMARY}; font-size:{T.FS_LG}px; padding: 4px;")
        return frame
