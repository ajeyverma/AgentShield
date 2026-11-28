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

import io
import logging
import os
import sys
from pathlib import Path

# PyInstaller with console=False sets sys.stdout and sys.stderr to None.
# If None, uvicorn and logging formatters crash with: AttributeError: 'NoneType' object has no attribute 'isatty'.
class DummyStream(io.StringIO):
    def isatty(self) -> bool:
        return False

if sys.stdout is None or not hasattr(sys.stdout, "isatty"):
    sys.stdout = DummyStream()
if sys.stderr is None or not hasattr(sys.stderr, "isatty"):
    sys.stderr = DummyStream()

# Ensure repository root is in sys.path
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Load all environment variables from candidate .env locations before reading settings
try:
    from dotenv import load_dotenv

    _exe_dir = Path(sys.executable).parent if getattr(sys, "frozen", False) else _REPO_ROOT
    _candidates = [
        _exe_dir / ".env",
        _exe_dir / "_internal" / ".env",
        _exe_dir / "demos" / "agent" / ".env",
        _exe_dir / "_internal" / "demos" / "agent" / ".env",
        _REPO_ROOT / ".env",
        _REPO_ROOT / "demos" / "agent" / ".env",
    ]
    for _env_path in _candidates:
        if _env_path.exists():
            load_dotenv(_env_path, override=False)
except Exception:
    pass

import threading
import time

from PySide6.QtWidgets import QApplication, QMessageBox

from agentshield.core.config import settings
from agentshield.core.logging import configure_logging

# Configure logging as early as possible
configure_logging(level=settings.log_level, fmt=settings.log_format)

logger = logging.getLogger("agentshield.desktop")


class EmbeddedBackendManager:
    """Manages the embedded FastAPI backend service lifecycle inside the desktop app."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8000):
        self.host = host
        self.port = port
        self._server = None
        self._thread: threading.Thread | None = None

    def is_healthy(self, timeout: float = 0.5) -> bool:
        """Check whether the backend is already responding to health probes."""
        try:
            import httpx
            resp = httpx.get(f"http://{self.host}:{self.port}/api/v1/health", timeout=timeout)
            return resp.status_code == 200
        except Exception:
            return False

    def start_if_needed(self, wait_timeout: float = 1.0) -> bool:
        """Start the embedded Uvicorn server in a daemon thread if not already running.
        
        Only waits up to 1.0s before opening the UI so launch is fast and smooth.
        """
        if self.is_healthy(timeout=0.2):
            logger.info("AgentShield backend is already running on %s:%d.", self.host, self.port)
            return True

        logger.info("Starting embedded AgentShield API backend on %s:%d...", self.host, self.port)
        try:
            import uvicorn
            from apps.api.main import create_app

            api_app = create_app()
            config = uvicorn.Config(
                app=api_app,
                host=self.host,
                port=self.port,
                log_level="warning",
                log_config=None,  # Safe in frozen GUI mode
                access_log=False,
                loop="asyncio",
            )
            self._server = uvicorn.Server(config)
            self._thread = threading.Thread(
                target=self._server.run,
                name="AgentShield-Embedded-API",
                daemon=True,
            )
            self._thread.start()

            # Brief wait (up to 1.0s) so UI doesn't delay startup
            deadline = time.time() + wait_timeout
            while time.time() < deadline:
                if self.is_healthy(timeout=0.15):
                    logger.info("Embedded AgentShield backend is now UP and HEALTHY.")
                    return True
                time.sleep(0.1)

            return True
        except Exception as exc:
            logger.exception("Failed to start embedded backend: %s", exc)
            return False

    def stop(self) -> None:
        """Signal embedded server to shut down cleanly."""
        if self._server:
            logger.info("Shutting down embedded AgentShield backend...")
            self._server.should_exit = True


def main() -> int:
    """Create and run the AgentShield AI desktop application.

    Returns:
        Exit code (0 = success).
    """
    # Standalone headless server flag
    if "--server" in sys.argv or "--backend" in sys.argv:
        import uvicorn
        from apps.api.main import create_app
        uvicorn.run(create_app(), host="127.0.0.1", port=settings.port)
        return 0

    backend_mgr = EmbeddedBackendManager(
        host=settings.host if settings.host not in ("0.0.0.0", "") else "127.0.0.1",
        port=settings.port,
    )

    try:
        # Start embedded backend first if needed
        backend_mgr.start_if_needed()

        app = QApplication(sys.argv)
        app.setApplicationName(settings.app_name)
        app.setApplicationVersion(settings.app_version)
        app.setOrganizationName("AgentShield AI")
        app.aboutToQuit.connect(backend_mgr.stop)

        # Import after QApplication creation to avoid PySide6 init ordering issues
        if "--chatbot" in sys.argv or "--agent" in sys.argv:
            from demos.agent.chatbot_ui import AgentChatbotWindow
            window = AgentChatbotWindow()
            window.show()
            logger.info("Subway Coders agent chatbot started directly.")
            exit_code = app.exec()
            backend_mgr.stop()
            return exit_code

        from apps.desktop.app.main_window import MainWindow
        from apps.desktop.themes.design_tokens import T  # noqa: PLC0415

        # Apply global light theme stylesheet (Phase 2)
        app.setStyleSheet(T.global_qss())

        window = MainWindow()
        window.show()

        logger.info(
            "AgentShield desktop application started with embedded backend.",
            extra={
                "version": settings.app_version,
                "backend_url": settings.backend_url,
                "env": settings.env.value,
            },
        )

        exit_code = app.exec()
        backend_mgr.stop()
        return exit_code

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
