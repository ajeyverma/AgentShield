"""Threat Monitoring view — Phase 5 with Backend Threat Detection Integration & Demo Fallback."""
from __future__ import annotations

import json
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QDialog, QDialogButtonBox, QGridLayout, QTextEdit, QScrollArea,
    QPushButton, QComboBox, QMessageBox,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.stat_card    import StatCard
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.status_badge import RiskBadge, StatusBadge
from apps.desktop.components.empty_state  import EmptyState
from apps.desktop.components.icons        import get_icon
from apps.desktop.services.backend_client import backend_client
from apps.desktop.utils import to_ist_str


def _threat_detail(t: dict | ThreatRecord, parent) -> None:
    dlg = QDialog(parent)
    is_dict = isinstance(t, dict)
    event_id = t.get("id") if is_dict else t.event_id
    dlg.setWindowTitle(f"Threat Finding Detail — {str(event_id)[:16]}")
    dlg.setMinimumWidth(580)
    dlg.setStyleSheet(
        f"QDialog {{ background:{T.SURFACE}; }} "
        f"QPushButton {{ padding: 6px 14px; font-weight: 600; border-radius: 6px; font-size: 13px; }} "
        f"QPushButton#secondary {{ background-color: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1; }} "
        f"QPushButton#secondary:hover {{ background-color: #E2E8F0; }}"
    )
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
    lay.setSpacing(T.SP_3)

    title_text = t.get("title") or t.get("threat_type") if is_dict else t.threat_type
    severity_val = t.get("severity", "MEDIUM") if is_dict else t.severity
    status_val = t.get("status", "open") if is_dict else t.status
    conf_val = t.get("confidence", "MEDIUM") if is_dict else "HIGH"

    top = QHBoxLayout()
    name_l = QLabel(title_text)
    name_l.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_LG}px; font-weight:700;")
    top.addWidget(name_l)
    top.addStretch()
    top.addWidget(RiskBadge(severity_val.capitalize()))
    top.addWidget(StatusBadge(status_val))
    lay.addLayout(top)

    sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color:{T.BORDER};")
    lay.addWidget(sep)

    grid = QGridLayout(); grid.setSpacing(T.SP_2)
    if is_dict:
        items = [
            ("Finding ID", str(t.get("id", ""))),
            ("Agent ID", str(t.get("agent_id", ""))),
            ("Detector", f"{t.get('detector_id', '')} (v{t.get('detector_version', '1.0')})"),
            ("Confidence", str(conf_val)),
            ("Affected Resource", str(t.get("affected_resource") or "None")),
            ("Detected At (IST)", to_ist_str(t.get("created_at"), with_tz=True)),
        ]
    else:
        items = [
            ("Event ID", t.event_id),
            ("Source Agent", t.source_agent),
            ("Affected Tool", t.affected_tool),
            ("Detected At (IST)", to_ist_str(t.detected_at, with_tz=True)),
        ]

    for i, (k, v) in enumerate(items):
        kl = QLabel(k + ":"); kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        vl = QLabel(v);       vl.setStyleSheet(f"color:{T.TEXT};")
        grid.addWidget(kl, i, 0); grid.addWidget(vl, i, 1)
    lay.addLayout(grid)

    desc_text = t.get("description", "") if is_dict else t.description
    rec_text = t.get("recommended_action", "") if is_dict else t.recommendation

    for section, text in [
        ("Description", desc_text),
        ("Recommended Response", rec_text),
    ]:
        s_lbl = QLabel(section + ":")
        s_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(s_lbl)
        t_lbl = QLabel(text)
        t_lbl.setWordWrap(True)
        t_lbl.setStyleSheet(
            f"color:{T.TEXT}; background:{T.SURFACE_ALT}; border:none;"
            f"border-radius:{T.R_SM}px; padding:{T.SP_3}px;"
        )
        lay.addWidget(t_lbl)

    # If dict and has evidence, display redacted evidence box
    if is_dict and t.get("evidence"):
        ev_lbl = QLabel("Redacted Evidence & Context:")
        ev_lbl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        lay.addWidget(ev_lbl)
        ev_txt = QTextEdit()
        ev_txt.setReadOnly(True)
        ev_txt.setFixedHeight(90)
        ev_txt.setText(json.dumps(t.get("evidence"), indent=2))
        ev_txt.setStyleSheet(
            f"color:{T.TEXT}; background:{T.SURFACE_ALT}; border:none;"
            f"border-radius:{T.R_SM}px; font-family:monospace; font-size:{T.FS_SM}px; padding:6px 10px;"
        )
        lay.addWidget(ev_txt)

    btn_row = QHBoxLayout()
    btn_row.setSpacing(T.SP_3)

    delete_btn = QPushButton("Delete Finding")
    delete_btn.setIcon(get_icon("trash", size=14, color="#DC2626"))
    delete_btn.setObjectName("danger")
    delete_btn.setMinimumHeight(34)
    delete_btn.setStyleSheet(
        f"QPushButton {{ background-color: #FEE2E2; color: #DC2626; border: 1px solid #FECACA; font-weight: 600; border-radius: 6px; padding: 6px 14px; font-size: 13px; }}"
        f"QPushButton:hover {{ background-color: #FCA5A5; color: #991B1B; }}"
    )

    def _on_delete():
        reply = QMessageBox.question(
            dlg,
            "Delete Threat Finding",
            "Are you sure you want to permanently delete this threat finding? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            finding_id = str(t.get("id") if is_dict else t.event_id)
            if backend_client.is_connected:
                backend_client.delete_threat_finding(finding_id)
            dlg.accept()
            if hasattr(parent, "refresh_data"):
                parent.refresh_data()

    delete_btn.clicked.connect(_on_delete)
    btn_row.addWidget(delete_btn)
    btn_row.addStretch()

    close_btn = QPushButton("Cancel / Close")
    close_btn.setObjectName("secondary")
    close_btn.setMinimumHeight(34)
    close_btn.setMinimumWidth(110)
    close_btn.setStyleSheet(
        f"QPushButton {{ background-color: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1; font-weight: 600; border-radius: 6px; padding: 6px 16px; font-size: 13px; }}"
        f"QPushButton:hover {{ background-color: #E2E8F0; }}"
    )
    close_btn.clicked.connect(dlg.reject)
    btn_row.addWidget(close_btn)

    lay.addLayout(btn_row)
    dlg.exec()


class ThreatMonitoringView(QWidget):
    """Threat monitoring — supports live backend threat findings with demo fallback."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        # Check if backend has live findings
        backend_connected = backend_client.is_connected
        live_findings = []
        live_summary = None
        if backend_connected:
            summary_resp = backend_client.get_threat_summary()
            if summary_resp:
                live_summary = summary_resp
            findings_resp = backend_client.get_threat_findings(size=25)
            if findings_resp and "items" in findings_resp:
                live_findings = findings_resp["items"]

        root.addWidget(PageHeader(
            "Threat Monitoring",
            "Real-time threat detection findings, provenance, and anomaly analysis.",
        ))

        # Stat cards
        if live_summary:
            total = live_summary.get("total_findings", 0)
            crit = live_summary.get("critical_findings", 0)
            high = live_summary.get("high_findings", 0)
            res = live_summary.get("open_findings", 0)
        else:
            total = len(live_findings)
            crit = sum(1 for f in live_findings if str(f.get("severity", "")).upper() == "CRITICAL")
            high = sum(1 for f in live_findings if str(f.get("severity", "")).upper() == "HIGH")
            res = sum(1 for f in live_findings if str(f.get("status", "")).lower() == "open")

        self._stat_cards = []
        cards_row = QHBoxLayout(); cards_row.setSpacing(T.SP_4)
        for title, val, col in [
            ("Total Findings",   str(total), T.PRIMARY),
            ("Critical",         str(crit),  T.DANGER),
            ("High Severity",    str(high),  T.WARNING),
            ("Active Open",      str(res),   T.INFO),
        ]:
            card = StatCard(title, val, accent_color=col)
            self._stat_cards.append(card)
            cards_row.addWidget(card)
        root.addLayout(cards_row)

        # Threat list
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        inner.setStyleSheet(f"background:{T.BG_APP};")
        self._inner_lay = QVBoxLayout(inner)
        self._inner_lay.setSpacing(T.SP_3)
        self._inner_lay.setContentsMargins(0, 0, 0, 0)

        if live_findings:
            for f in live_findings:
                card = self._make_finding_card(f)
                self._inner_lay.addWidget(card)
        else:
            empty = EmptyState("shield", "No security threats detected. Agents are operating safely.")
            self._inner_lay.addWidget(empty)

        self._inner_lay.addStretch()
        scroll.setWidget(inner)
        root.addWidget(scroll, stretch=1)

    def refresh_data(self):
        live_findings = []
        live_summary = None
        if backend_client.is_connected:
            summary_resp = backend_client.get_threat_summary()
            if summary_resp:
                live_summary = summary_resp
            findings_resp = backend_client.get_threat_findings(size=25)
            if findings_resp and "items" in findings_resp:
                live_findings = findings_resp["items"]

        if live_summary:
            total = live_summary.get("total_findings", 0)
            crit = live_summary.get("critical_findings", 0)
            high = live_summary.get("high_findings", 0)
            res = live_summary.get("open_findings", 0)
        else:
            total = len(live_findings)
            crit = sum(1 for f in live_findings if str(f.get("severity", "")).upper() == "CRITICAL")
            high = sum(1 for f in live_findings if str(f.get("severity", "")).upper() == "HIGH")
            res = sum(1 for f in live_findings if str(f.get("status", "")).lower() == "open")

        vals = [str(total), str(crit), str(high), str(res)]
        for i, card in enumerate(self._stat_cards):
            if i < len(vals):
                card.set_value(vals[i])

        if hasattr(self, "_inner_lay"):
            while self._inner_lay.count() > 1:
                item = self._inner_lay.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            if live_findings:
                for idx, f in enumerate(live_findings):
                    card = self._make_finding_card(f)
                    self._inner_lay.insertWidget(idx, card)
            else:
                empty = EmptyState("shield", "No security threats detected. Agents are operating safely.")
                self._inner_lay.insertWidget(0, empty)

    def _make_finding_card(self, f: dict) -> QFrame:
        severity = f.get("severity", "MEDIUM").capitalize()
        BORDER_COLOR = {
            "Critical": T.DANGER,
            "High": T.WARNING,
            "Medium": T.INFO,
            "Low": T.SUCCESS,
        }.get(severity, T.BORDER)

        card = QFrame()
        card.setObjectName("threatCard")
        card.setStyleSheet(
            f"QFrame#threatCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-left:4px solid {BORDER_COLOR}; border-radius:{T.R_LG}px; }} QLabel {{ border: none; }}"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(T.SP_4, T.SP_3, T.SP_4, T.SP_3)
        lay.setSpacing(T.SP_4)

        left = QVBoxLayout(); left.setSpacing(2)
        title_l = QLabel(f.get("title", "Threat Finding"))
        title_l.setStyleSheet(f"color:{T.TEXT}; font-weight:700; font-size:{T.FS_MD}px; background:transparent;")
        agent_id_str = str(f.get("agent_id", ""))[:12]
        detector_id = f.get("detector_id", "")
        time_str = to_ist_str(f.get("created_at"), with_tz=True)
        sub_l = QLabel(f"Agent: {agent_id_str}  •  Detector: {detector_id}  •  {time_str}")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;")
        left.addWidget(title_l); left.addWidget(sub_l)
        lay.addLayout(left, 2)

        lay.addWidget(RiskBadge(severity))
        lay.addWidget(StatusBadge(f.get("status", "open")))
        detail_btn = QPushButton("Details")
        detail_btn.setObjectName("secondary")
        detail_btn.setFixedWidth(80)
        detail_btn.clicked.connect(lambda _, rec=f: _threat_detail(rec, self))
        lay.addWidget(detail_btn)
        return card

    def _make_threat_card(self, t: ThreatRecord) -> QFrame:
        BORDER_COLOR = {
            "Critical": T.DANGER,
            "High": T.WARNING,
            "Medium": T.INFO,
            "Low": T.SUCCESS,
        }.get(t.severity, T.BORDER)

        card = QFrame()
        card.setObjectName("threatCard")
        card.setStyleSheet(
            f"QFrame#threatCard {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-left:4px solid {BORDER_COLOR}; border-radius:{T.R_LG}px; }} QLabel {{ border: none; }}"
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

        lay.addWidget(RiskBadge(t.severity))
        lay.addWidget(StatusBadge(t.status))
        detail_btn = QPushButton("Details")
        detail_btn.setObjectName("secondary")
        detail_btn.setFixedWidth(80)
        detail_btn.clicked.connect(lambda _, rec=t: _threat_detail(rec, self))
        lay.addWidget(detail_btn)
        return card
