"""
AgentShield AI — Security and Operational Metrics (Phase 11).

Provides thread-safe in-memory counters, gauges, and latency histograms for
runtime security decisions, threat severity distributions, approval rates,
and gateway operational latencies without exposing sensitive tenant data.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any


class SecurityMetricsCollector:
    """Thread-safe collector for runtime security and operational performance metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Decision metrics
        self._decisions: dict[str, int] = defaultdict(int)

        # Threat metrics
        self._threats_by_severity: dict[str, int] = defaultdict(int)
        self._threats_by_category: dict[str, int] = defaultdict(int)

        # Operational metrics
        self._requests_total: int = 0
        self._errors_total: int = 0
        self._latencies_ms: list[float] = []
        self._gateway_latencies_ms: list[float] = []

        # Approval metrics
        self._approvals_requested: int = 0
        self._approvals_granted: int = 0
        self._approvals_rejected: int = 0
        self._approvals_expired: int = 0

        # Repeated blocks & violations
        self._repeated_blocks_count: int = 0
        self._unauthorized_attempts: int = 0

    def record_decision(self, decision: str) -> None:
        with self._lock:
            d = decision.upper()
            self._decisions[d] += 1
            if d == "BLOCK":
                self._repeated_blocks_count += 1

    def record_threat(self, severity: str, category: str) -> None:
        with self._lock:
            self._threats_by_severity[severity.upper()] += 1
            self._threats_by_category[category.lower()] += 1

    def record_approval_lifecycle(self, action: str) -> None:
        with self._lock:
            act = action.lower()
            if act == "request":
                self._approvals_requested += 1
            elif act == "grant":
                self._approvals_granted += 1
            elif act == "reject":
                self._approvals_rejected += 1
            elif act == "expire":
                self._approvals_expired += 1

    def record_unauthorized_attempt(self) -> None:
        with self._lock:
            self._unauthorized_attempts += 1

    def record_api_request(self, status_code: int, duration_ms: float) -> None:
        with self._lock:
            self._requests_total += 1
            if status_code >= 400:
                self._errors_total += 1
            self._latencies_ms.append(duration_ms)
            if len(self._latencies_ms) > 1000:
                self._latencies_ms.pop(0)

    def record_gateway_latency(self, duration_ms: float) -> None:
        with self._lock:
            self._gateway_latencies_ms.append(duration_ms)
            if len(self._gateway_latencies_ms) > 1000:
                self._gateway_latencies_ms.pop(0)

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            # Latency percentiles
            lats = sorted(self._latencies_ms) if self._latencies_ms else [0.0]
            gw_lats = sorted(self._gateway_latencies_ms) if self._gateway_latencies_ms else [0.0]

            def p(arr: list[float], pct: float) -> float:
                if not arr:
                    return 0.0
                idx = int(len(arr) * pct)
                idx = min(idx, len(arr) - 1)
                return round(arr[idx], 2)

            total_appr_decided = self._approvals_granted + self._approvals_rejected
            approval_rate = (
                round((self._approvals_granted / total_appr_decided) * 100.0, 1)
                if total_appr_decided > 0
                else 100.0
            )

            return {
                "security": {
                    "total_allow": self._decisions.get("ALLOW", 0),
                    "total_block": self._decisions.get("BLOCK", 0),
                    "total_ask_human": self._decisions.get("ASK_HUMAN", 0),
                    "threats_by_severity": dict(self._threats_by_severity),
                    "threats_by_category": dict(self._threats_by_category),
                    "repeated_blocked_actions": self._repeated_blocks_count,
                    "unauthorized_attempts": self._unauthorized_attempts,
                    "approvals": {
                        "requested": self._approvals_requested,
                        "granted": self._approvals_granted,
                        "rejected": self._approvals_rejected,
                        "expired": self._approvals_expired,
                        "approval_rate_pct": approval_rate,
                    },
                },
                "operational": {
                    "total_api_requests": self._requests_total,
                    "total_errors": self._errors_total,
                    "error_rate_pct": round((self._errors_total / self._requests_total * 100.0), 2)
                    if self._requests_total > 0
                    else 0.0,
                    "api_latency_ms": {
                        "avg": round(sum(lats) / len(lats), 2) if lats else 0.0,
                        "p50": p(lats, 0.50),
                        "p95": p(lats, 0.95),
                        "p99": p(lats, 0.99),
                    },
                    "gateway_latency_ms": {
                        "avg": round(sum(gw_lats) / len(gw_lats), 2) if gw_lats else 0.0,
                        "p50": p(gw_lats, 0.50),
                        "p95": p(gw_lats, 0.95),
                        "p99": p(gw_lats, 0.99),
                    },
                },
            }


metrics_collector = SecurityMetricsCollector()
