"""Threat Monitoring view — Phase 2 demo data only."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QDialog, QDialogButtonBox, QGridLayout, QTextEdit, QScrollArea,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.stat_card    import StatCard
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.status_badge import RiskBadge, StatusBadge
from apps.desktop.services.demo_data      import THREATS, ThreatRecord, get_dashboard_stats


def _threat_detail(t: ThreatRecord, parent) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(f"Threat Detail — {t.event_id}")
    dlg.setMinimumWidth(540)
    dlg.setStyleSheet(f"background:{T.SURFACE};")
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
    lay.setSpacing(T.SP_3)

    top = QHBoxLayout()
    name_l = QLabel(t.threat_type)
    name_l.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_XL}px; font-weight:700;")
    top.addWidget(name_l)
    top.addStretch()
    top.addWidget(RiskBadge(t.severity))
    top.addWidget(StatusBadge(t.status))
    lay.addLayout(top)

    sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color:{T.BORDER};")
    lay.addWidget(sep)

    grid = QGridLayout(); grid.setSpacing(T.SP_2)
    items = [
        ("Event ID",       t.event_id),
        ("Source Agent",   t.source_agent),
        ("Affected Tool",  t.affected_tool),
        ("Detected At",    t.detected_at),
    ]
    for i, (k, v) in enumerate(items):
        kl = QLabel(k + ":"); kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        vl = QLabel(v);       vl.setStyleSheet(f"color:{T.TEXT};")
        grid.addWidget(kl, i, 0); grid.addWidget(vl, i, 1)
    lay.addLayout(grid)

    for section, text in [
        ("Description",          t.description),
        ("Reason for Classification", t.reason),
        ("Recommended Response", t.recommendation),
    ]:
        s_lbl = QLabel(section + ":")
        s_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(s_lbl)
        t_lbl = QLabel(text)
        t_lbl.setWordWrap(True)
        t_lbl.setStyleSheet(
            f"color:{T.TEXT}; background:{T.SURFACE_ALT}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_SM}px; padding:{T.SP_3}px;"
        )
        lay.addWidget(t_lbl)

    btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    btns.rejected.connect(dlg.reject)
    lay.addWidget(btns)
    dlg.exec()


class ThreatMonitoringView(QWidget):
    """Threat monitoring — demo data, no real detection."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Threat Monitoring",
            "Detected security events and anomalies for review.",
            demo_note="DEMO DATA — No real threat detection",
        ))

        # Stat cards
        stats = get_dashboard_stats()
        total = len(THREATS)
        crit  = stats["critical_threats"]
        high  = stats["high_threats"]
        res   = stats["resolved_threats"]

        cards_row = QHBoxLayout(); cards_row.setSpacing(T.SP_4)
        for title, val, col in [
            ("Total Events",     str(total), T.PRIMARY),
            ("Critical",         str(crit),  T.DANGER),
            ("High Severity",    str(high),  T.WARNING),
            ("Resolved",         str(res),   T.SUCCESS),
        ]:
            cards_row.addWidget(StatCard(title, val, accent_color=col))
        root.addLayout(cards_row)

        # Threat list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        inner.setStyleSheet(f"background:{T.BG_APP};")
        inner_lay = QVBoxLayout(inner)
        inner_lay.setSpacing(T.SP_3)
        inner_lay.setContentsMargins(0, 0, 0, 0)

        for t in THREATS:
            card = self._make_threat_card(t)
            inner_lay.addWidget(card)
        inner_lay.addStretch()
        scroll.setWidget(inner)
        root.addWidget(scroll)

    def _make_threat_card(self, t: ThreatRecord) -> QFrame:
        BORDER_COLOR = {
            "Critical": T.DANGER,
            "High": T.WARNING,
            "Medium": T.INFO,
            "Low": T.SUCCESS,
        }.get(t.severity, T.BORDER)

        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-left:4px solid {BORDER_COLOR}; border-radius:{T.R_LG}px; }}"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(T.SP_4, T.SP_3, T.SP_4, T.SP_3)
        lay.setSpacing(T.SP_4)

        left = QVBoxLayout(); left.setSpacing(2)
        name_l = QLabel(t.threat_type)
        name_l.setStyleSheet(f"color:{T.TEXT}; font-weight:700; font-size:{T.FS_MD}px; background:transparent;")
        sub_l = QLabel(f"Agent: {t.source_agent}  •  Tool: {t.affected_tool}  •  {t.detected_at[11:16]}")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;")
        left.addWidget(name_l); left.addWidget(sub_l)
        lay.addLayout(left, 2)

        from PySide6.QtWidgets import QPushButton
        lay.addWidget(RiskBadge(t.severity))
        lay.addWidget(StatusBadge(t.status))
        detail_btn = QPushButton("Details")
        detail_btn.setObjectName("secondary")
        detail_btn.setFixedWidth(80)
        detail_btn.clicked.connect(lambda _, rec=t: _threat_detail(rec, self))
        lay.addWidget(detail_btn)
        return card
