"""
AgentShield AI — Phase 2 Design Tokens (extended).

Single source of truth for all visual values used across the desktop UI.
Import `T` and access class attributes — never scatter literals in widget code.

Usage::

    from apps.desktop.themes.design_tokens import T

    widget.setStyleSheet(f"background:{T.SURFACE}; color:{T.TEXT_PRIMARY};")
"""
from __future__ import annotations


class T:
    """Flat namespace of all design tokens."""

    # ── Backgrounds ──────────────────────────────────────────────────────────
    BG_APP        = "#F5F7FA"   # Outermost window fill
    SURFACE       = "#FFFFFF"   # Cards, panels
    SURFACE_ALT   = "#F8FAFC"   # Subtle alternate rows / recessed areas
    SIDEBAR_BG    = "#1E293B"   # Dark sidebar
    SIDEBAR_HOVER = "#2D3F55"
    SIDEBAR_ACTIVE= "#2563EB"   # Active nav item

    # ── Primary accent ───────────────────────────────────────────────────────
    PRIMARY       = "#2563EB"
    PRIMARY_HOVER = "#1D4ED8"
    PRIMARY_LIGHT = "#EFF6FF"

    # ── Text ─────────────────────────────────────────────────────────────────
    TEXT          = "#172033"
    TEXT_PRIMARY  = "#172033"
    TEXT_SEC      = "#64748B"
    TEXT_MUTED    = "#94A3B8"
    TEXT_ON_DARK  = "#F1F5F9"   # Text on sidebar / dark surfaces
    TEXT_ON_PRIMARY = "#FFFFFF"

    # ── Borders ──────────────────────────────────────────────────────────────
    BORDER        = "#E2E8F0"
    BORDER_FOCUS  = "#2563EB"

    # ── Semantic ─────────────────────────────────────────────────────────────
    SUCCESS       = "#16A34A"
    SUCCESS_BG    = "#F0FDF4"
    WARNING       = "#D97706"
    WARNING_BG    = "#FFFBEB"
    DANGER        = "#DC2626"
    DANGER_BG     = "#FEF2F2"
    INFO          = "#0284C7"
    INFO_BG       = "#F0F9FF"

    # ── Decision badges ──────────────────────────────────────────────────────
    ALLOW_FG      = "#15803D"
    ALLOW_BG      = "#DCFCE7"
    BLOCK_FG      = "#B91C1C"
    BLOCK_BG      = "#FEE2E2"
    ASK_FG        = "#92400E"
    ASK_BG        = "#FEF3C7"

    # ── Risk badges ──────────────────────────────────────────────────────────
    RISK_NONE_FG  = "#64748B"
    RISK_NONE_BG  = "#F1F5F9"
    RISK_LOW_FG   = "#15803D"
    RISK_LOW_BG   = "#DCFCE7"
    RISK_MED_FG   = "#92400E"
    RISK_MED_BG   = "#FEF3C7"
    RISK_HIGH_FG  = "#C2410C"
    RISK_HIGH_BG  = "#FFEDD5"
    RISK_CRIT_FG  = "#B91C1C"
    RISK_CRIT_BG  = "#FEE2E2"

    # ── Typography ───────────────────────────────────────────────────────────
    FONT_FAMILY   = "Segoe UI, Inter, -apple-system, sans-serif"
    FS_XS   = 10
    FS_SM   = 11
    FS_BASE = 12
    FS_MD   = 13
    FS_LG   = 15
    FS_XL   = 18
    FS_2XL  = 22
    FS_3XL  = 28

    # ── Spacing (px integers) ─────────────────────────────────────────────────
    SP_1 = 4
    SP_2 = 8
    SP_3 = 12
    SP_4 = 16
    SP_5 = 20
    SP_6 = 24
    SP_8 = 32
    SP_10= 40

    # ── Radius ───────────────────────────────────────────────────────────────
    R_SM = 4
    R_MD = 6
    R_LG = 8
    R_XL = 12

    # ── Layout ───────────────────────────────────────────────────────────────
    SIDEBAR_W   = 220
    HEADER_H    = 56
    STAT_CARD_H = 100

    # ── Chart colours (sequential) ───────────────────────────────────────────
    CHART_ALLOW  = "#16A34A"
    CHART_BLOCK  = "#DC2626"
    CHART_ASK    = "#D97706"
    CHART_SERIES = ["#2563EB", "#16A34A", "#D97706", "#DC2626", "#7C3AED"]

    # ── QSS helpers ──────────────────────────────────────────────────────────
    @classmethod
    def card_style(cls) -> str:
        return (
            f"background:{cls.SURFACE};"
            f"border:1px solid {cls.BORDER};"
            f"border-radius:{cls.R_LG}px;"
        )

    @classmethod
    def badge_style(cls, fg: str, bg: str, r: int = 4) -> str:
        return (
            f"color:{fg};background:{bg};"
            f"border-radius:{r}px;"
            f"padding:2px 8px;"
            f"font-size:{cls.FS_SM}px;"
            f"font-weight:600;"
        )

    @classmethod
    def global_qss(cls) -> str:
        """Full application-level QSS reset."""
        return f"""
            * {{
                font-family: {cls.FONT_FAMILY};
            }}
            QWidget {{
                font-size: {cls.FS_BASE}px;
                color: {cls.TEXT};
                background-color: {cls.BG_APP};
            }}
            QMainWindow {{
                background-color: {cls.BG_APP};
            }}
            QDialog {{
                background-color: {cls.SURFACE};
            }}
            QLabel {{
                background: transparent;
                color: {cls.TEXT};
                border: none;
            }}
            QPushButton {{
                background-color: {cls.PRIMARY};
                color: {cls.TEXT_ON_PRIMARY};
                border: none;
                border-radius: {cls.R_SM}px;
                padding: 4px 10px;
                font-size: {cls.FS_SM}px;
                font-weight: 500;
                min-height: 24px;
            }}
            QPushButton:hover {{
                background-color: {cls.PRIMARY_HOVER};
            }}
            QPushButton:pressed {{
                background-color: {cls.PRIMARY_HOVER};
            }}
            QPushButton:disabled {{
                background-color: {cls.BORDER};
                color: {cls.TEXT_MUTED};
            }}
            QPushButton#secondary {{
                background-color: {cls.SURFACE};
                color: {cls.TEXT};
                border: 1px solid {cls.BORDER};
            }}
            QPushButton#secondary:hover {{
                background-color: {cls.SURFACE_ALT};
            }}
            QPushButton#danger {{
                background-color: {cls.DANGER};
                color: white;
            }}
            QPushButton#danger:hover {{
                background-color: #B91C1C;
            }}
            QPushButton#success {{
                background-color: {cls.SUCCESS};
                color: white;
            }}
            QPushButton#success:hover {{
                background-color: #15803D;
            }}
            QLineEdit {{
                background-color: {cls.SURFACE};
                border: 1px solid {cls.BORDER};
                border-radius: {cls.R_SM}px;
                padding: 3px 8px;
                color: {cls.TEXT};
                min-height: 24px;
                font-size: {cls.FS_SM}px;
                selection-background-color: {cls.PRIMARY};
            }}
            QLineEdit:focus {{
                border-color: {cls.BORDER_FOCUS};
                outline: none;
            }}
            QTextEdit, QPlainTextEdit {{
                background-color: {cls.SURFACE};
                border: 1px solid {cls.BORDER};
                border-radius: {cls.R_SM}px;
                padding: 4px 8px;
                color: {cls.TEXT};
                font-size: {cls.FS_SM}px;
                selection-background-color: {cls.PRIMARY};
            }}
            QTextEdit:focus, QPlainTextEdit:focus {{
                border-color: {cls.BORDER_FOCUS};
                outline: none;
            }}
            QComboBox {{
                background-color: {cls.SURFACE};
                border: 1px solid {cls.BORDER};
                border-radius: {cls.R_SM}px;
                padding: 3px 8px;
                color: {cls.TEXT};
                min-height: 24px;
                font-size: {cls.FS_SM}px;
            }}
            QComboBox:focus {{
                border-color: {cls.BORDER_FOCUS};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 18px;
            }}
            QComboBox QAbstractItemView {{
                background: {cls.SURFACE};
                border: 1px solid {cls.BORDER};
                selection-background-color: {cls.PRIMARY_LIGHT};
                selection-color: {cls.PRIMARY};
                outline: none;
            }}
            QTableWidget {{
                background-color: {cls.SURFACE};
                border: 1px solid {cls.BORDER};
                border-radius: {cls.R_MD}px;
                gridline-color: {cls.BORDER};
                outline: none;
            }}
            QTableWidget::item {{
                padding: 8px 12px;
                border-bottom: 1px solid {cls.BORDER};
                color: {cls.TEXT};
            }}
            QTableWidget::item:selected {{
                background-color: {cls.PRIMARY_LIGHT};
                color: {cls.TEXT};
            }}
            QHeaderView::section {{
                background-color: {cls.SURFACE_ALT};
                color: {cls.TEXT_SEC};
                font-size: {cls.FS_SM}px;
                font-weight: 600;
                padding: 8px 12px;
                border: none;
                border-bottom: 1px solid {cls.BORDER};
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            QScrollBar:vertical {{
                background: {cls.SURFACE_ALT};
                width: 8px;
                border-radius: 4px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {cls.BORDER};
                border-radius: 4px;
                min-height: 24px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {cls.TEXT_MUTED};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar:horizontal {{
                background: {cls.SURFACE_ALT};
                height: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:horizontal {{
                background: {cls.BORDER};
                border-radius: 4px;
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QSplitter::handle {{
                background: {cls.BORDER};
            }}
            QTabWidget::pane {{
                border: 1px solid {cls.BORDER};
                border-radius: {cls.R_MD}px;
                background: {cls.SURFACE};
            }}
            QTabBar::tab {{
                background: {cls.SURFACE_ALT};
                border: 1px solid {cls.BORDER};
                border-bottom: none;
                padding: 7px 16px;
                color: {cls.TEXT_SEC};
                font-weight: 500;
            }}
            QTabBar::tab:selected {{
                background: {cls.SURFACE};
                color: {cls.PRIMARY};
                font-weight: 600;
            }}
            QCheckBox {{
                color: {cls.TEXT};
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {cls.BORDER};
                border-radius: 3px;
                background: {cls.SURFACE};
            }}
            QCheckBox::indicator:checked {{
                background: {cls.PRIMARY};
                border-color: {cls.PRIMARY};
            }}
            QStatusBar {{
                background: {cls.SURFACE};
                border-top: 1px solid {cls.BORDER};
                font-size: {cls.FS_SM}px;
                color: {cls.TEXT_SEC};
            }}
            QToolTip {{
                background: {cls.TEXT};
                color: {cls.TEXT_ON_DARK};
                border: none;
                padding: 4px 8px;
                border-radius: {cls.R_SM}px;
                font-size: {cls.FS_SM}px;
            }}
        """
