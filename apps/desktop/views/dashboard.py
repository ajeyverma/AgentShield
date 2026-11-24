"""Dashboard view — Phase 2 demo data only."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.stat_card    import StatCard
from apps.desktop.components.status_badge import DecisionBadge, RiskBadge, StatusBadge
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.mini_chart   import BarChartWidget, DonutChartWidget
from apps.desktop.services.backend_client import backend_client


def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("dashboardCard")
    frame.setStyleSheet(
        f"QFrame#dashboardCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
        f"border-radius:{T.R_LG}px; }} QLabel {{ border: none; }}"
    )
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(T.SP_4, T.SP_4, T.SP_4, T.SP_4)
    lay.setSpacing(T.SP_3)
    if title:
        lbl = QLabel(title)
        lbl.setStyleSheet(
            f"color:{T.TEXT}; font-size:{T.FS_MD}px; font-weight:700; background:transparent; border:none;"
        )
        lay.addWidget(lbl)
    return frame, lay


class DashboardView(QWidget):
    """Main dashboard — unified real security overview."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._stats = {
            "total_agents": 0,
            "active_agents": 0,
            "actions_today": 0,
            "blocked_today": 0,
            "pending_approvals": 0,
            "allow_count": 0,
            "block_count": 0,
            "ask_count": 0,
            "critical_threats": 0,
            "high_threats": 0,
            "resolved_threats": 0,
            "trend_allow": [0] * 10,
            "trend_block": [0] * 10,
        }
        # Fetch real metrics if backend connected
        try:
            live = backend_client.get_metrics_summary()
            if live and "counters" in live:
                c = live["counters"]
                g = live.get("gauges", {})
                if "security.requests.total" in c:
                    self._stats["actions_today"] = c["security.requests.total"]
                if "security.decisions.BLOCK" in c:
                    self._stats["blocked_today"] = c["security.decisions.BLOCK"]
                if "security.alerts.active" in g:
                    self._stats["pending_approvals"] = int(g["security.alerts.active"])

            agents = backend_client.get_agents()
            if agents:
                self._stats["total_agents"] = len(agents)
                self._stats["active_agents"] = sum(1 for a in agents if str(a.get("status", "")).lower() == "active")
        except Exception:
            pass
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_5)

        # Header
        root.addWidget(PageHeader(
            "Dashboard",
            "Security overview and recent activity summary.",
        ))

        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content.setStyleSheet(f"background:{T.BG_APP};")
        lay = QVBoxLayout(content)
        lay.setSpacing(T.SP_5)
        lay.setContentsMargins(0, 0, 0, 0)

        # ── Stat cards ──────────────────────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(T.SP_4)
        s = self._stats
        cards = [
            ("Total Agents",      str(s["total_agents"]),      "Connected agent connectors", T.PRIMARY),
            ("Active Agents",     str(s["active_agents"]),      "Currently processing tasks", T.SUCCESS),
            ("Actions Today",     str(s["actions_today"]),      "Security evaluations",        T.INFO),
            ("Blocked Actions",   str(s["blocked_today"]),      "Prevented by policy",         T.DANGER),
            ("Pending Approvals", str(s["pending_approvals"]),  "Awaiting human decision",     T.WARNING),
        ]
        for title, val, sub, col in cards:
            c = StatCard(title, val, sub, accent_color=col)
            stats_row.addWidget(c)
        lay.addLayout(stats_row)

        # ── Charts row ──────────────────────────────────────────────────────
        charts_row = QHBoxLayout()
        charts_row.setSpacing(T.SP_4)

        # Trend chart
        trend_frame, trend_lay = _card("Activity Trend (Last 10 Periods)")
        trend_chart = BarChartWidget(s["trend_allow"], s["trend_block"])
        trend_chart.setMinimumHeight(160)
        # Legend
        leg = QHBoxLayout()
        for color, label in [(T.CHART_ALLOW, "Allow"), (T.CHART_BLOCK, "Block")]:
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{color}; background:transparent; font-size:16px;")
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color:{T.TEXT_SEC}; background:transparent; font-size:{T.FS_SM}px;")
            leg.addWidget(dot)
            leg.addWidget(lbl)
            leg.addSpacing(T.SP_3)
        leg.addStretch()
        trend_lay.addWidget(trend_chart)
        trend_lay.addLayout(leg)
        charts_row.addWidget(trend_frame, 3)

        # Donut chart
        donut_frame, donut_lay = _card("Decision Distribution")
        donut = DonutChartWidget([
            ("Allow",    s["allow_count"],  T.CHART_ALLOW),
            ("Block",    s["block_count"],  T.CHART_BLOCK),
            ("Ask Human",s["ask_count"],    T.CHART_ASK),
        ])
        donut_lay.addWidget(donut)
        charts_row.addWidget(donut_frame, 2)

        lay.addLayout(charts_row)

        # ── Recent activity table ───────────────────────────────────────────
        act_frame, act_lay = _card("Recent Activity")
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(["Time", "Agent", "Tool", "Operation", "Decision", "Status"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.setShowGrid(False)
        table.setStyleSheet(
            f"QTableWidget {{ background:{T.SURFACE}; border:none; outline:none; }}"
            f"QTableWidget::item:alternate {{ background:{T.SURFACE_ALT}; }}"
            f"QTableWidget::item {{ padding:6px 12px; }}"
        )

        real_executions = []
        if backend_client.is_connected:
            resp = backend_client.list_executions(size=8)
            if resp and "items" in resp:
                real_executions = resp["items"]

        if real_executions:
            for rec in real_executions:
                r = table.rowCount()
                table.insertRow(r)
                table.setItem(r, 0, QTableWidgetItem(str(rec.get("created_at", ""))[:19]))
                table.setItem(r, 1, QTableWidgetItem(str(rec.get("agent_id", ""))[:12]))
                table.setItem(r, 2, QTableWidgetItem(str(rec.get("tool_name", ""))))
                table.setItem(r, 3, QTableWidgetItem(str(rec.get("action_name", ""))))
                # Decision badge
                dec_str = str(rec.get("decision", "ALLOW"))
                dec = DecisionBadge(dec_str)
                table.setCellWidget(r, 4, dec)
                table.setItem(r, 4, QTableWidgetItem(dec_str))
                # Status badge
                st_str = str(rec.get("status", "COMPLETED"))
                sb = StatusBadge(st_str)
                table.setCellWidget(r, 5, sb)
                table.setItem(r, 5, QTableWidgetItem(st_str))
                table.setRowHeight(r, 36)
        else:
            table.insertRow(0)
            empty_item = QTableWidgetItem("No recent activity recorded.")
            empty_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            table.setItem(0, 0, empty_item)
            table.setSpan(0, 0, 1, 6)

        table.setMaximumHeight(320)
        act_lay.addWidget(table)
        lay.addWidget(act_frame)

        # ── Recent threats ──────────────────────────────────────────────────
        thr_frame, thr_lay = _card("Recent Security Events")
        real_threats = []
        if backend_client.is_connected:
            t_resp = backend_client.get_threats()
            if t_resp:
                real_threats = t_resp if isinstance(t_resp, list) else t_resp.get("items", [])

        if real_threats:
            for t in real_threats[:4]:
                row_w = QWidget()
                row_w.setStyleSheet(f"background:transparent;")
                row_h = QHBoxLayout(row_w)
                row_h.setContentsMargins(0, 4, 0, 4)
                row_h.setSpacing(T.SP_3)

                sev = str(t.get("severity", "MEDIUM")).capitalize()
                sev_badge = RiskBadge(sev)
                sev_badge.setFixedWidth(70)
                row_h.addWidget(sev_badge)

                info_col = QVBoxLayout()
                info_col.setSpacing(1)
                title_l = QLabel(str(t.get("threat_type") or t.get("title", "Threat Event")))
                title_l.setStyleSheet(f"color:{T.TEXT}; font-weight:600; background:transparent; border:none;")
                sub_l = QLabel(f"Agent: {str(t.get('agent_id', ''))[:12]}  •  {str(t.get('created_at', ''))[:19]}")
                sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent; border:none;")
                info_col.addWidget(title_l)
                info_col.addWidget(sub_l)
                row_h.addLayout(info_col)
                row_h.addStretch()

                status_b = StatusBadge(str(t.get("status", "Open")).capitalize())
                row_h.addWidget(status_b)

                thr_lay.addWidget(row_w)
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.HLine)
                sep.setStyleSheet(f"background:{T.BORDER}; border:none; max-height:1px;")
                thr_lay.addWidget(sep)
        else:
            no_thr = QLabel("No security threat events recorded.")
            no_thr.setStyleSheet(f"color:{T.TEXT_MUTED}; font-size:{T.FS_SM}px; padding:12px;")
            no_thr.setAlignment(Qt.AlignmentFlag.AlignCenter)
            thr_lay.addWidget(no_thr)

        lay.addWidget(thr_frame)
        lay.addStretch()

        scroll.setWidget(content)
        root.addWidget(scroll)
