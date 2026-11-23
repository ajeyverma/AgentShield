"""
AgentShield AI — Distributed Tracing and Context Management (Phase 11).

Provides lightweight context propagation for correlation_id, trace_id, and span_id
across API endpoints, gateway executions, MCP reverse proxies, and threat analysis.
OpenTelemetry compatible without requiring external heavyweight daemons.
"""

from __future__ import annotations

import contextvars
import logging
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Generator

from agentshield.security.sanitization import redact_secrets

logger = logging.getLogger("agentshield.observability.tracing")

# Contextvars for trace and correlation propagation
_current_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("current_trace_id", default="")
_current_span_id: contextvars.ContextVar[str] = contextvars.ContextVar("current_span_id", default="")
_current_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("current_correlation_id", default="")


def generate_trace_id() -> str:
    """Generate 32-character lowercase hex trace ID."""
    return uuid.uuid4().hex


def generate_span_id() -> str:
    """Generate 16-character lowercase hex span ID."""
    return uuid.uuid4().hex[:16]


def get_current_trace_id() -> str:
    tid = _current_trace_id.get()
    if not tid:
        tid = generate_trace_id()
        _current_trace_id.set(tid)
    return tid


def get_current_span_id() -> str:
    sid = _current_span_id.get()
    if not sid:
        sid = generate_span_id()
        _current_span_id.set(sid)
    return sid


def get_current_correlation_id() -> str:
    cid = _current_correlation_id.get()
    if not cid:
        cid = str(uuid.uuid4())
        _current_correlation_id.set(cid)
    return cid


def set_trace_context(trace_id: str | None = None, span_id: str | None = None, correlation_id: str | None = None) -> None:
    """Explicitly establish tracing context from incoming HTTP or MCP headers."""
    if trace_id:
        _current_trace_id.set(trace_id)
    if span_id:
        _current_span_id.set(span_id)
    if correlation_id:
        _current_correlation_id.set(correlation_id)


@dataclass
class TraceSpan:
    name: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    correlation_id: str
    start_time: float = field(default_factory=time.perf_counter)
    end_time: float | None = None
    duration_ms: float = 0.0
    status: str = "OK"
    attributes: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None

    def finish(self, status: str = "OK", error: Exception | None = None) -> None:
        self.end_time = time.perf_counter()
        self.duration_ms = round((self.end_time - self.start_time) * 1000.0, 3)
        self.status = status
        if error:
            self.status = "ERROR"
            self.error_message = str(error)
            self.attributes["error"] = True
            self.attributes["error.type"] = error.__class__.__name__


@contextmanager
def trace_span(
    name: str,
    attributes: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Generator[TraceSpan, None, None]:
    """Context manager to measure component latency and propagate parent-child spans safely."""
    trace_id = get_current_trace_id()
    parent_span_id = _current_span_id.get() or None
    new_span_id = generate_span_id()
    correlation_id = get_current_correlation_id()

    # Scrub attributes of any sensitive keys/tokens
    combined_attrs = dict(attributes or {})
    combined_attrs.update(kwargs)
    clean_attrs = redact_secrets(combined_attrs)

    span = TraceSpan(
        name=name,
        trace_id=trace_id,
        span_id=new_span_id,
        parent_span_id=parent_span_id,
        correlation_id=correlation_id,
        attributes=clean_attrs,
    )

    token = _current_span_id.set(new_span_id)
    try:
        yield span
        span.finish(status="OK")
    except Exception as exc:
        span.finish(status="ERROR", error=exc)
        raise
    finally:
        _current_span_id.reset(token)
