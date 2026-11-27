"""AgentShield AI — Desktop Application Entry Point.

Run the desktop application:
    python apps/desktop/main.py

The desktop application communicates with the AgentShield backend through
the URL configured in AGENTSHIELD_BACKEND_URL.  The backend does NOT need
to be running for the desktop application to start — it displays a
connection status indicator in the header bar.

This module is intentionally thin.  All UI construction is delegated to
MainWindow.  Error handling here catches unrecoverable startup failures
and surfaces them to the user before the application exits.
"""

from __future__ import annotations

import logging
import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from agentshield.core.config import settings
from agentshield.core.logging import configure_logging

# Configure logging as early as possible
configure_logging(level=settings.log_level, fmt=settings.log_format)

logger = logging.getLogger("agentshield.desktop")


def main() -> int:
    """Create and run the AgentShield AI desktop application.

    Returns:
        Exit code (0 = success).
    """
    try:
        app = QApplication(sys.argv)
        app.setApplicationName(settings.app_name)
        app.setApplicationVersion(settings.app_version)
        app.setOrganizationName("AgentShield AI")

        # Import after QApplication creation to avoid PySide6 init ordering issues
        if "--chatbot" in sys.argv or "--agent" in sys.argv:
            from demos.agent.chatbot_ui import AgentChatbotWindow
            window = AgentChatbotWindow()
            window.show()
            logger.info("Subway Coders agent chatbot started directly.")
            return app.exec()

        from apps.desktop.app.main_window import MainWindow
        from apps.desktop.themes.design_tokens import T  # noqa: PLC0415

        # Apply global light theme stylesheet (Phase 2)
        app.setStyleSheet(T.global_qss())

        window = MainWindow()
        window.show()

        logger.info(
            "AgentShield desktop application started.",
            extra={
                "version": settings.app_version,
                "backend_url": settings.backend_url,
                "env": settings.env.value,
            },
        )

        return app.exec()

    except Exception as exc:  # noqa: BLE001
        logger.exception("Fatal error during desktop application startup.")
        # Attempt to show a user-visible error dialog even if the main window failed
        try:
            error_app = QApplication.instance() or QApplication(sys.argv)
            QMessageBox.critical(
                None,
                "AgentShield AI — Startup Error",
                f"The application could not start.\n\n{exc}\n\n"
                "Check the log output for details.",
            )
        except Exception:  # noqa: BLE001
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
