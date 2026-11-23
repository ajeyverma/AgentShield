"""Backend client stub (Phase 2 — not yet connected to real backend).

All methods return None / empty.  Replace method bodies with real HTTP calls
using httpx in Phase 3+ when backend authentication is implemented.

Design contract:
  - Desktop views MUST call these methods, not reach into demo_data directly.
  - Swapping this for a real implementation requires no changes in views.
"""
from __future__ import annotations
import logging

logger = logging.getLogger("agentshield.desktop.backend_client")


class BackendClient:
    """Thin async-ready stub for future backend communication."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self._connected = False
        logger.debug("BackendClient initialised (stub mode)", extra={"url": base_url})

    # ── Connection ────────────────────────────────────────────────────────────

    async def check_health(self) -> dict | None:
        """Return health payload or None if unreachable."""
        return None   # Phase 2: not connected

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ── Stubs (Phase 3+ will implement real HTTP calls) ──────────────────────

    async def get_agents(self):         return None
    async def get_activity(self):       return None
    async def get_threats(self):        return None
    async def get_approvals(self):      return None
    async def get_policies(self):       return None
    async def get_audit_logs(self):     return None
    async def get_dashboard_stats(self):return None
