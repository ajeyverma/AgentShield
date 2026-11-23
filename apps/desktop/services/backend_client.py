"""
AgentShield AI — Desktop Backend Client (Phase 3).

Centralized HTTP client for communication between the PySide6 desktop UI
and the FastAPI security backend.

Designed to be executed in background worker threads (QThread / QRunnable)
so the Qt main event loop is never blocked.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from apps.desktop.config.settings import BACKEND_URL

logger = logging.getLogger("agentshield.desktop.backend_client")


class BackendClient:
    """Robust, authenticated HTTP client for AgentShield backend APIs."""

    def __init__(self, base_url: str | None = None, timeout: float = 4.0) -> None:
        self.base_url = (base_url or BACKEND_URL).rstrip("/")
        self.api_prefix = "/api/v1"
        self.timeout = timeout
        self.token: str | None = None
        self.current_user: dict[str, Any] | None = None
        self._connected: bool = False
        self._client: httpx.Client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
        )

    @property
    def is_connected(self) -> bool:
        return self._connected

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def close(self) -> None:
        """Close underlying HTTP client connections."""
        self._client.close()

    # ── Connection & Health ──────────────────────────────────────────────────

    def check_health(self) -> dict[str, Any] | None:
        """Verify if backend is reachable. Updates is_connected flag."""
        try:
            resp = self._client.get(f"{self.api_prefix}/health")
            if resp.status_code == 200:
                self._connected = True
                return resp.json()
            self._connected = False
            return None
        except (httpx.ConnectError, httpx.TimeoutException, Exception) as exc:
            logger.debug("Backend unreachable during health check: %s", exc)
            self._connected = False
            return None

    # ── Authentication ───────────────────────────────────────────────────────

    def login(self, username_or_email: str, password: str) -> bool:
        """Authenticate user and store access token in memory."""
        try:
            resp = self._client.post(
                f"{self.api_prefix}/auth/login",
                json={"username_or_email": username_or_email, "password": password},
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("access_token")
                self.current_user = data.get("user")
                self._connected = True
                logger.info("Desktop client logged in as %s", self.current_user.get("username") if self.current_user else "user")
                return True
            return False
        except Exception as exc:
            logger.warning("Desktop login failed: %s", exc)
            return False

    def register(self, email: str, username: str, password: str) -> dict[str, Any] | None:
        """Register a new user account."""
        try:
            resp = self._client.post(
                f"{self.api_prefix}/auth/register",
                json={"email": email, "username": username, "password": password},
            )
            if resp.status_code == 201:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Registration failed: %s", exc)
            return None

    def logout(self) -> None:
        """Clear session token."""
        self.token = None
        self.current_user = None

    # ── Dashboard ────────────────────────────────────────────────────────────

    def get_dashboard_stats(self) -> dict[str, Any] | None:
        """Fetch real aggregated metrics from the backend for the current user."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/dashboard/summary",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch dashboard stats: %s", exc)
            return None

    # ── Agents ───────────────────────────────────────────────────────────────

    def get_agents(self) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/agents",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch agents: %s", exc)
            return None

    def create_agent(self, name: str, framework: str = "custom", description: str | None = None) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/agents",
                headers=self._headers(),
                json={"agent_name": name, "framework": framework, "description": description},
            )
            if resp.status_code == 201:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to create agent: %s", exc)
            return None

    def rotate_agent_credential(self, agent_id: str) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/agents/{agent_id}/rotate-credential",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to rotate credential: %s", exc)
            return None

    # ── Activity ─────────────────────────────────────────────────────────────

    def get_activity(self, page: int = 1, size: int = 50) -> dict[str, Any] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/activity?page={page}&size={size}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch activity: %s", exc)
            return None

    # ── Threats ──────────────────────────────────────────────────────────────

    def get_threats(self) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/threats",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch threats: %s", exc)
            return None

    def update_threat_status(self, threat_id: str, status: str) -> dict[str, Any] | None:
        try:
            resp = self._client.patch(
                f"{self.api_prefix}/threats/{threat_id}",
                headers=self._headers(),
                json={"status": status},
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to update threat: %s", exc)
            return None

    # ── Approvals ────────────────────────────────────────────────────────────

    def get_approvals(self) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/approvals",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch approvals: %s", exc)
            return None

    def update_approval(self, approval_id: str, status: str) -> dict[str, Any] | None:
        try:
            resp = self._client.patch(
                f"{self.api_prefix}/approvals/{approval_id}",
                headers=self._headers(),
                json={"status": status},
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to update approval: %s", exc)
            return None

    # ── Policies ─────────────────────────────────────────────────────────────

    def get_policies(self) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/policies",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch policies: %s", exc)
            return None

    # ── Audit Logs ───────────────────────────────────────────────────────────

    def get_audit_logs(self) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/audit-logs",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch audit logs: %s", exc)
            return None

    # ── Integrations ─────────────────────────────────────────────────────────

    def get_integrations(self) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/integrations",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch integrations: %s", exc)
            return None

    # ── WebSocket URL ────────────────────────────────────────────────────────

    def get_websocket_url(self) -> str:
        """Construct the authenticated WebSocket subscription URL."""
        parsed = urlparse(self.base_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        netloc = parsed.netloc or parsed.path
        url = f"{ws_scheme}://{netloc}{self.api_prefix}/ws/events"
        if self.token:
            url += f"?token={self.token}"
        return url


# Module-level default instance
backend_client = BackendClient()
