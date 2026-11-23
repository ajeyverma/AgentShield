"""
AgentShield AI — Structured JSON Logging (Phase 11).

Provides JSON-formatted operational and security logging with sensitive data
redaction and distributed trace correlation.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from agentshield.observability.tracing import (
    get_current_correlation_id,
    get_current_span_id,
    get_current_trace_id,
)
from agentshield.security.sanitization import redact_secrets


class StructuredJsonFormatter(logging.Formatter):
    """Custom logging formatter outputting clean, machine-parsable JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "trace_id": get_current_trace_id(),
            "span_id": get_current_span_id(),
            "correlation_id": get_current_correlation_id(),
        }

        # Include custom record attributes if provided
        if hasattr(record, "tenant_id"):
            log_entry["tenant_id"] = record.tenant_id
        if hasattr(record, "component"):
            log_entry["component"] = record.component
        if hasattr(record, "event_type"):
            log_entry["event_type"] = record.event_type

        # Include exception information if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Sanitize entire log dictionary to prevent credential leakage
        sanitized = redact_secrets(log_entry)
        return json.dumps(sanitized, default=str)
