"""
AgentShield AI — Desktop Application Design Tokens.

All visual design values (colours, typography, spacing, borders, shadows)
are defined here as a single source of truth.  Widgets MUST import from
this module rather than hard-coding style values.

Theme: Light — Professional cybersecurity aesthetic.

Usage
─────
    from apps.desktop.themes.tokens import LightTheme as T

    widget.setStyleSheet(f"background-color: {T.SURFACE}; color: {T.TEXT_PRIMARY};")
"""

from __future__ import annotations


class LightTheme:
    """Design tokens for the AgentShield AI light theme."""

    # ------------------------------------------------------------------
    # Brand colours
    # ------------------------------------------------------------------
    BRAND_PRIMARY = "#1B6CA8"       # Deep blue — primary actions, headers
    BRAND_PRIMARY_HOVER = "#155A8F"
    BRAND_ACCENT = "#00A3BF"        # Teal accent — highlights, active states
    BRAND_ACCENT_HOVER = "#008EA8"

    # ------------------------------------------------------------------
    # Background layers
    # ------------------------------------------------------------------
    BACKGROUND = "#F4F6F9"          # App background (outermost layer)
    SURFACE = "#FFFFFF"             # Card / panel background
    SURFACE_RAISED = "#FFFFFF"      # Elevated surface (dialogs)
    SURFACE_RECESSED = "#EEF1F5"    # Recessed input / sidebar background

    # ------------------------------------------------------------------
    # Text
    # ------------------------------------------------------------------
    TEXT_PRIMARY = "#1A202C"        # Main body text
    TEXT_SECONDARY = "#4A5568"      # Subdued labels and captions
    TEXT_TERTIARY = "#718096"       # Placeholder text
    TEXT_ON_BRAND = "#FFFFFF"       # Text on brand-coloured backgrounds
    TEXT_LINK = "#1B6CA8"

    # ------------------------------------------------------------------
    # Border / dividers
    # ------------------------------------------------------------------
    BORDER_DEFAULT = "#D1D9E6"
    BORDER_FOCUSED = "#1B6CA8"
    BORDER_SUBTLE = "#E8ECF2"
    DIVIDER = "#E2E8F0"

    # ------------------------------------------------------------------
    # Status / semantic colours
    # ------------------------------------------------------------------
    SUCCESS = "#2D7D46"
    SUCCESS_SURFACE = "#E8F5EC"
    WARNING = "#B45309"
    WARNING_SURFACE = "#FEF3C7"
    ERROR = "#C53030"
    ERROR_SURFACE = "#FFF5F5"
    INFO = "#2B6CB0"
    INFO_SURFACE = "#EBF4FF"

    # ------------------------------------------------------------------
    # Decision colours (ALLOW / BLOCK / ASK_HUMAN)
    # ------------------------------------------------------------------
    DECISION_ALLOW = "#2D7D46"
    DECISION_ALLOW_SURFACE = "#E8F5EC"
    DECISION_BLOCK = "#C53030"
    DECISION_BLOCK_SURFACE = "#FFF5F5"
    DECISION_ASK_HUMAN = "#B45309"
    DECISION_ASK_HUMAN_SURFACE = "#FEF3C7"

    # ------------------------------------------------------------------
    # Risk level colours
    # ------------------------------------------------------------------
    RISK_NONE = "#718096"
    RISK_LOW = "#2D7D46"
    RISK_MEDIUM = "#B45309"
    RISK_HIGH = "#C05621"
    RISK_CRITICAL = "#C53030"

    # ------------------------------------------------------------------
    # Interactive states
    # ------------------------------------------------------------------
    HOVER_OVERLAY = "rgba(27, 108, 168, 0.06)"
    SELECTED_OVERLAY = "rgba(27, 108, 168, 0.12)"
    DISABLED_OPACITY = "0.45"

    # ------------------------------------------------------------------
    # Typography
    # ------------------------------------------------------------------
    FONT_FAMILY = "Segoe UI, Inter, -apple-system, BlinkMacSystemFont, sans-serif"
    FONT_SIZE_XS = "10px"
    FONT_SIZE_SM = "12px"
    FONT_SIZE_BASE = "13px"
    FONT_SIZE_MD = "14px"
    FONT_SIZE_LG = "16px"
    FONT_SIZE_XL = "20px"
    FONT_SIZE_2XL = "24px"
    FONT_WEIGHT_REGULAR = "400"
    FONT_WEIGHT_MEDIUM = "500"
    FONT_WEIGHT_SEMIBOLD = "600"
    FONT_WEIGHT_BOLD = "700"

    # ------------------------------------------------------------------
    # Spacing (multiples of 4px)
    # ------------------------------------------------------------------
    SPACE_1 = "4px"
    SPACE_2 = "8px"
    SPACE_3 = "12px"
    SPACE_4 = "16px"
    SPACE_5 = "20px"
    SPACE_6 = "24px"
    SPACE_8 = "32px"
    SPACE_10 = "40px"
    SPACE_12 = "48px"

    # ------------------------------------------------------------------
    # Border radius
    # ------------------------------------------------------------------
    RADIUS_SM = "4px"
    RADIUS_MD = "6px"
    RADIUS_LG = "8px"
    RADIUS_XL = "12px"
    RADIUS_FULL = "9999px"

    # ------------------------------------------------------------------
    # Elevation / shadows (expressed as QSS-compatible box-shadow hints)
    # ------------------------------------------------------------------
    SHADOW_SM = "0 1px 3px rgba(0,0,0,0.08)"
    SHADOW_MD = "0 4px 12px rgba(0,0,0,0.10)"
    SHADOW_LG = "0 8px 24px rgba(0,0,0,0.12)"

    # ------------------------------------------------------------------
    # Component-level defaults
    # ------------------------------------------------------------------
    SIDEBAR_WIDTH = 220
    HEADER_HEIGHT = 56
    INPUT_HEIGHT = "24px"
    BUTTON_HEIGHT = "24px"

    @classmethod
    def global_stylesheet(cls) -> str:
        """Return a minimal global QSS stylesheet for the application.

        This sets sensible defaults so that all widgets inherit a consistent
        base style.  Component-specific styles are applied at the widget level.
        """
        return f"""
            QWidget {{
                font-family: {cls.FONT_FAMILY};
                font-size: {cls.FONT_SIZE_BASE};
                color: {cls.TEXT_PRIMARY};
                background-color: {cls.BACKGROUND};
            }}
            QMainWindow {{
                background-color: {cls.BACKGROUND};
            }}
            QLabel {{
                background: transparent;
            }}
            QPushButton {{
                background-color: {cls.BRAND_PRIMARY};
                color: {cls.TEXT_ON_BRAND};
                border: none;
                border-radius: {cls.RADIUS_SM};
                padding: 4px 10px;
                font-size: {cls.FONT_SIZE_SM};
                font-weight: {cls.FONT_WEIGHT_MEDIUM};
                min-height: {cls.BUTTON_HEIGHT};
            }}
            QPushButton:hover {{
                background-color: {cls.BRAND_PRIMARY_HOVER};
            }}
            QPushButton:disabled {{
                background-color: {cls.BORDER_DEFAULT};
                color: {cls.TEXT_TERTIARY};
            }}
            QLineEdit {{
                background-color: {cls.SURFACE};
                border: 1px solid {cls.BORDER_DEFAULT};
                border-radius: {cls.RADIUS_SM};
                padding: 3px 8px;
                color: {cls.TEXT_PRIMARY};
                min-height: {cls.INPUT_HEIGHT};
                selection-background-color: {cls.BRAND_PRIMARY};
            }}
            QTextEdit, QPlainTextEdit {{
                background-color: {cls.SURFACE};
                border: 1px solid {cls.BORDER_DEFAULT};
                border-radius: {cls.RADIUS_SM};
                padding: 4px 8px;
                color: {cls.TEXT_PRIMARY};
                selection-background-color: {cls.BRAND_PRIMARY};
            }}
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
                border-color: {cls.BORDER_FOCUSED};
            }}
            QScrollBar:vertical {{
                background: {cls.SURFACE_RECESSED};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {cls.BORDER_DEFAULT};
                border-radius: 4px;
                min-height: 24px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {cls.TEXT_TERTIARY};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            QMenuBar {{
                background-color: {cls.SURFACE};
                border-bottom: 1px solid {cls.BORDER_SUBTLE};
            }}
            QStatusBar {{
                background-color: {cls.SURFACE};
                border-top: 1px solid {cls.BORDER_SUBTLE};
                font-size: {cls.FONT_SIZE_SM};
                color: {cls.TEXT_SECONDARY};
            }}
        """
