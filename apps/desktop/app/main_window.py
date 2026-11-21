"""
AgentShield AI — Desktop Application Main Window.

The main window is a minimal container for Phase 1.  It establishes:
  - Application title and size.
  - Light-theme styling.
  - A status bar with backend connection target.
  - A placeholder central widget ready for Phase 2 navigation.

Phase 2 will add the sidebar navigation, dashboard view, and all
content panels.  Nothing from the security engine runs in this process.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from apps.desktop.config.settings import APP_NAME, APP_VERSION, BACKEND_URL
from apps.desktop.themes.tokens import LightTheme as T

logger = logging.getLogger("agentshield.desktop.main_window")


class MainWindow(QMainWindow):
    """AgentShield AI main application window (Phase 1 — foundation only)."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_window()
        self._setup_central_widget()
        self._setup_status_bar()
        logger.info("Main window initialized.", extra={"backend_url": BACKEND_URL})

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup_window(self) -> None:
        """Configure window title, size, and minimum dimensions."""
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1_100, 700)
        self.resize(1_280, 800)

    def _setup_central_widget(self) -> None:
        """Create the Phase 1 placeholder central widget."""
        central = QWidget()
        central.setObjectName("centralWidget")
        layout = QVBoxLayout(central)
        layout.setContentsMargins(48, 48, 48, 48)
        layout.setSpacing(16)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Application name heading
        title_label = QLabel(APP_NAME)
        title_font = QFont()
        title_font.setPointSize(28)
        title_font.setWeight(QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"color: {T.BRAND_PRIMARY}; background: transparent;")

        # Subtitle
        subtitle_label = QLabel("Universal Runtime Security Gateway for AI Agents")
        subtitle_font = QFont()
        subtitle_font.setPointSize(13)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet(f"color: {T.TEXT_SECONDARY}; background: transparent;")

        # Version / phase badge
        phase_label = QLabel(f"Version {APP_VERSION}  •  Phase 1 — Foundation")
        phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        phase_label.setStyleSheet(
            f"color: {T.TEXT_TERTIARY}; "
            f"font-size: {T.FONT_SIZE_SM}; "
            "background: transparent;"
        )

        # Backend target info
        backend_label = QLabel(f"Backend: {BACKEND_URL}")
        backend_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        backend_label.setStyleSheet(
            f"color: {T.INFO}; "
            f"font-size: {T.FONT_SIZE_SM}; "
            "background: transparent;"
        )

        layout.addStretch()
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        layout.addWidget(phase_label)
        layout.addSpacing(8)
        layout.addWidget(backend_label)
        layout.addStretch()

        self.setCentralWidget(central)

    def _setup_status_bar(self) -> None:
        """Configure the application status bar."""
        status_bar = QStatusBar()
        status_bar.setObjectName("statusBar")
        status_bar.showMessage(
            f"AgentShield AI {APP_VERSION}  |  Phase 1 Foundation  |  Backend: {BACKEND_URL}"
        )
        self.setStatusBar(status_bar)
