"""Reusable badge / pill widgets for decisions, risk levels, and status."""
from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel
from apps.desktop.themes.design_tokens import T


class StatusBadge(QLabel):
    """Generic coloured pill badge."""

    _PALETTE: dict[str, tuple[str, str]] = {
        # (fg, bg)
        "Active":        (T.SUCCESS, T.SUCCESS_BG),
        "Idle":          (T.TEXT_SEC, T.SURFACE_ALT),
        "Disconnected":  (T.TEXT_MUTED, T.SURFACE_ALT),
        "Error":         (T.DANGER, T.DANGER_BG),
        "Normal":        (T.SUCCESS, T.SUCCESS_BG),
        "Elevated":      (T.WARNING, T.WARNING_BG),
        "High":          (T.DANGER, T.DANGER_BG),
        "Critical":      (T.DANGER, T.DANGER_BG),
        "Active-thr":    (T.DANGER, T.DANGER_BG),
        "Investigating": (T.WARNING, T.WARNING_BG),
        "Resolved":      (T.SUCCESS, T.SUCCESS_BG),
        "Pending":       (T.WARNING, T.WARNING_BG),
        "Approved":      (T.SUCCESS, T.SUCCESS_BG),
        "Rejected":      (T.DANGER, T.DANGER_BG),
        "Draft":         (T.TEXT_SEC, T.SURFACE_ALT),
        "Inactive":      (T.TEXT_MUTED, T.SURFACE_ALT),
        "Planned":       (T.INFO, T.INFO_BG),
        "Not Configured":(T.TEXT_SEC, T.SURFACE_ALT),
        "UI Demo":       (T.PRIMARY, T.PRIMARY_LIGHT),
        "Completed":     (T.SUCCESS, T.SUCCESS_BG),
        "Blocked":       (T.DANGER, T.DANGER_BG),
        "Pending Approval": (T.WARNING, T.WARNING_BG),
        "Failed":        (T.DANGER, T.DANGER_BG),
        "Success":       (T.SUCCESS, T.SUCCESS_BG),
    }

    def __init__(self, status: str, parent=None) -> None:
        super().__init__(status, parent)
        fg, bg = self._PALETTE.get(status, (T.TEXT_SEC, T.SURFACE_ALT))
        self.setStyleSheet(T.badge_style(fg, bg))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(22)


class DecisionBadge(QLabel):
    """ALLOW / BLOCK / ASK_HUMAN badge."""

    _MAP = {
        "ALLOW":     (T.ALLOW_FG,  T.ALLOW_BG,  "ALLOW"),
        "BLOCK":     (T.BLOCK_FG,  T.BLOCK_BG,  "BLOCK"),
        "ASK_HUMAN": (T.ASK_FG,   T.ASK_BG,    "ASK HUMAN"),
    }

    def __init__(self, decision: str, parent=None) -> None:
        fg, bg, label = self._MAP.get(decision, (T.TEXT_SEC, T.SURFACE_ALT, decision))
        super().__init__(label, parent)
        self.setStyleSheet(T.badge_style(fg, bg))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(22)


class RiskBadge(QLabel):
    """NONE / LOW / MEDIUM / HIGH / CRITICAL risk badge."""

    _MAP = {
        "NONE":     (T.RISK_NONE_FG, T.RISK_NONE_BG),
        "LOW":      (T.RISK_LOW_FG,  T.RISK_LOW_BG),
        "MEDIUM":   (T.RISK_MED_FG,  T.RISK_MED_BG),
        "HIGH":     (T.RISK_HIGH_FG, T.RISK_HIGH_BG),
        "CRITICAL": (T.RISK_CRIT_FG, T.RISK_CRIT_BG),
        # Threat severities (mixed case)
        "Critical": (T.RISK_CRIT_FG, T.RISK_CRIT_BG),
        "High":     (T.RISK_HIGH_FG, T.RISK_HIGH_BG),
        "Medium":   (T.RISK_MED_FG,  T.RISK_MED_BG),
        "Low":      (T.RISK_LOW_FG,  T.RISK_LOW_BG),
    }

    def __init__(self, risk: str, parent=None) -> None:
        fg, bg = self._MAP.get(risk, (T.TEXT_SEC, T.SURFACE_ALT))
        super().__init__(risk.upper() if risk.isupper() else risk, parent)
        self.setStyleSheet(T.badge_style(fg, bg))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(22)
