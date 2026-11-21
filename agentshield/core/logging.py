"""
AgentShield AI — Structured Logging Configuration.

Provides a single configure_logging() function that sets up structured
logging for both the backend (FastAPI / uvicorn) and the desktop
application.

Two output modes are supported:

    console — Human-readable coloured output (development).
    json    — Structured JSON output (production / log aggregation).

Usage
─────
    from agentshield.core.logging import configure_logging
    configure_logging(level="INFO", fmt="console")

    import logging
    logger = logging.getLogger("agentshield.my_module")
    logger.info("Service started", extra={"version": "0.1.0"})
"""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO", fmt: str = "console") -> None:
    """Configure the root logger for AgentShield.

    Args:
        level: One of DEBUG, INFO, WARNING, ERROR, CRITICAL.
        fmt:   'console' for human-readable output, 'json' for structured JSON.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    if fmt == "json":
        formatter = _JsonFormatter()
    else:
        formatter = _ConsoleFormatter()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(numeric_level)
    root.handlers.clear()
    root.addHandler(handler)

    # Silence noisy third-party loggers in production
    for noisy in ("uvicorn.access", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


class _ConsoleFormatter(logging.Formatter):
    """Coloured, human-readable log formatter for development."""

    _LEVEL_COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self._LEVEL_COLORS.get(record.levelname, "")
        level_tag = f"{color}[{record.levelname:<8}]{self._RESET}"
        name_tag = f"\033[90m{record.name}\033[0m"
        message = super().format(record)
        # Strip the default formatting and rebuild
        record_msg = record.getMessage()
        return f"{self.formatTime(record, '%H:%M:%S')} {level_tag} {name_tag} — {record_msg}"


class _JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter for production / log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import UTC, datetime

        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)
