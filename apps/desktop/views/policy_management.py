"""Policy Management view — Phase 2 demo data only."""
from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QScrollArea, QDialog, QDialogButtonBox, QGridLayout,
)
from apps.desktop.themes.design_tokens import T
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.status_badge import StatusBadge
from apps.desktop.services.demo_data      import POLICIES, PolicyRecord


ENFORCEMENT_COLORS = {
    "Block":          (T.BLOCK_FG,  T.BLOCK_BG),
    "Ask Human":      (T.ASK_FG,   T.ASK_BG),
    "Allow with Log": (T.ALLOW_FG,  T.ALLOW_BG),
}


def _policy_detail(pol: PolicyRecord, parent) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(f"Policy — {pol.policy_id}")
    dlg.setMinimumWidth(520)
    dlg.setStyleSheet(f"background:{T.SURFACE};")
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_5)
    lay.setSpacing(T.SP_4)

    top = QHBoxLayout()
    name_l = QLabel(pol.name)
    name_l.setWordWrap(True)
    name_l.setStyleSheet(f"color:{T.TEXT}; font-size:{T.FS_LG}px; font-weight:700;")
    top.addWidget(name_l, 1)
    top.addWidget(StatusBadge(pol.status))
    lay.addLayout(top)

    sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet(f"color:{T.BORDER};"); lay.addWidget(sep)

    grid = QGridLayout(); grid.setSpacing(T.SP_2)
    for i, (k, v) in enumerate([
        ("Policy ID",    pol.policy_id),
        ("Category",     pol.category),
        ("Enforcement",  pol.enforcement),
        ("Scope",        pol.scope),
        ("Last Updated", pol.last_updated),
    ]):
        kl = QLabel(k + ":"); kl.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
        vl = QLabel(v);       vl.setStyleSheet(f"color:{T.TEXT};")
        grid.addWidget(kl, i, 0); grid.addWidget(vl, i, 1)
    lay.addLayout(grid)

    desc_l = QLabel("Description:")
    desc_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
    lay.addWidget(desc_l)
    desc = QLabel(pol.description)
    desc.setWordWrap(True)
    desc.setStyleSheet(f"color:{T.TEXT}; padding:{T.SP_2}px;")
    lay.addWidget(desc)

    rules_l = QLabel("Rules (illustrative):")
    rules_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-weight:600; font-size:{T.FS_SM}px;")
    lay.addWidget(rules_l)
    rules = QLabel("\n".join(f"  • {r}" for r in pol.rules))
    rules.setStyleSheet(
        f"color:{T.TEXT}; background:{T.SURFACE_ALT}; border:1px solid {T.BORDER};"
        f"border-radius:{T.R_SM}px; padding:{T.SP_3}px; font-family:monospace; font-size:{T.FS_SM}px;"
    )
    lay.addWidget(rules)

    note = QLabel("⚠ Demo only: Policy engine not implemented in Phase 2.")
    note.setStyleSheet(
        f"color:{T.WARNING}; background:{T.WARNING_BG}; padding:{T.SP_2}px;"
        f"border-radius:{T.R_SM}px; font-size:{T.FS_SM}px;"
    )
    lay.addWidget(note)

    btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    btns.rejected.connect(dlg.reject)
    lay.addWidget(btns)
    dlg.exec()


class PolicyManagementView(QWidget):
    """Policy management — demo data, no real policy engine."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_6, T.SP_5, T.SP_6, T.SP_6)
        root.setSpacing(T.SP_4)

        root.addWidget(PageHeader(
            "Policy Management",
            "Security policies governing agent tool access.",
            demo_note="DEMO DATA — Policy engine not implemented",
        ))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        inner.setStyleSheet(f"background:{T.BG_APP};")
        inner_lay = QVBoxLayout(inner)
        inner_lay.setSpacing(T.SP_3)
        inner_lay.setContentsMargins(0, 0, 0, 0)

        for pol in POLICIES:
            inner_lay.addWidget(self._make_policy_card(pol))
        inner_lay.addStretch()
        scroll.setWidget(inner)
        root.addWidget(scroll)

    def _make_policy_card(self, pol: PolicyRecord) -> QFrame:
        enf_fg, enf_bg = ENFORCEMENT_COLORS.get(pol.enforcement, (T.TEXT_SEC, T.SURFACE_ALT))

        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"border-radius:{T.R_LG}px; }}"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(T.SP_4, T.SP_3, T.SP_4, T.SP_3)
        lay.setSpacing(T.SP_4)

        # Category icon
        icon_map = {"File System": "📁", "Network": "🌐", "Terminal": "💻",
                    "Database": "🗄", "Code Execution": "⚡"}
        icon_l = QLabel(icon_map.get(pol.category, "🔒"))
        icon_l.setStyleSheet("font-size:20px; background:transparent;")
        icon_l.setFixedWidth(30)
        lay.addWidget(icon_l)

        left = QVBoxLayout(); left.setSpacing(2)
        name_l = QLabel(pol.name)
        name_l.setStyleSheet(f"color:{T.TEXT}; font-weight:700; font-size:{T.FS_MD}px; background:transparent;")
        sub_l = QLabel(f"Category: {pol.category}  •  Scope: {pol.scope}  •  Updated: {pol.last_updated}")
        sub_l.setStyleSheet(f"color:{T.TEXT_SEC}; font-size:{T.FS_SM}px; background:transparent;")
        left.addWidget(name_l); left.addWidget(sub_l)
        lay.addLayout(left, 2)

        # Enforcement badge
        enf_badge = QLabel(pol.enforcement)
        enf_badge.setStyleSheet(T.badge_style(enf_fg, enf_bg))
        lay.addWidget(enf_badge)

        lay.addWidget(StatusBadge(pol.status))

        detail_btn = QPushButton("Details")
        detail_btn.setObjectName("secondary")
        detail_btn.setFixedWidth(80)
        detail_btn.clicked.connect(lambda _, p=pol: _policy_detail(p, self))
        lay.addWidget(detail_btn)

        return card
