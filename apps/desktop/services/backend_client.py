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

    # ── Security Core (Phase 4) ──────────────────────────────────────────────

    def evaluate_action(self, action_request: dict[str, Any]) -> dict[str, Any] | None:
        """Submit an ActionRequest to the security core for evaluation."""
        try:
            resp = self._client.post(
                f"{self.api_prefix}/security/evaluate",
                headers=self._headers(),
                json=action_request,
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Action evaluation request failed: %s", exc)
            return None

    def get_security_decisions(
        self,
        page: int = 1,
        size: int = 50,
        agent_id: str | None = None,
        decision: str | None = None,
        risk_level: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch historical security decisions."""
        try:
            params = [f"page={page}", f"size={size}"]
            if agent_id:
                params.append(f"agent_id={agent_id}")
            if decision:
                params.append(f"decision={decision}")
            if risk_level:
                params.append(f"risk_level={risk_level}")
            qs = "&".join(params)
            resp = self._client.get(
                f"{self.api_prefix}/security/decisions?{qs}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch security decisions: %s", exc)
            return None

    def get_security_decision(self, decision_id: str) -> dict[str, Any] | None:
        """Retrieve a single security decision by ID."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/security/decisions/{decision_id}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch decision %s: %s", decision_id, exc)
            return None

    # ── Threat Detection (Phase 5) ───────────────────────────────────────────

    def analyze_threats(
        self,
        action_request_data: dict[str, Any],
        provenance_data: dict[str, Any] | None = None,
        relevant_history: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Submit action for threat detection analysis without executing."""
        try:
            payload = {
                "action_request": action_request_data,
                "provenance": provenance_data,
                "relevant_history": relevant_history or [],
            }
            resp = self._client.post(
                f"{self.api_prefix}/threat-detection/analyze",
                json=payload,
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Threat analysis failed: %s", exc)
            return None

    def get_threat_findings(
        self,
        agent_id: str | None = None,
        threat_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> dict[str, Any] | None:
        """Fetch granular threat findings with pagination and filters."""
        try:
            params = [f"page={page}", f"size={size}"]
            if agent_id:
                params.append(f"agent_id={agent_id}")
            if threat_type:
                params.append(f"threat_type={threat_type}")
            if severity:
                params.append(f"severity={severity}")
            if status:
                params.append(f"status={status}")
            qs = "&".join(params)
            resp = self._client.get(
                f"{self.api_prefix}/threat-detection/findings?{qs}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch threat findings: %s", exc)
            return None

    def get_threat_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Fetch single threat finding by ID with evidence."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/threat-detection/findings/{finding_id}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch finding %s: %s", finding_id, exc)
            return None

    def update_threat_finding_status(self, finding_id: str, status: str) -> dict[str, Any] | None:
        """Update threat finding status."""
        try:
            resp = self._client.patch(
                f"{self.api_prefix}/threat-detection/findings/{finding_id}",
                json={"status": status},
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to update finding %s status: %s", finding_id, exc)
            return None

    def get_threat_summary(self) -> dict[str, Any] | None:
        """Fetch high-level threat statistics and category distribution."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/threat-detection/summary",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch threat summary: %s", exc)
            return None

    def get_detectors(self) -> list[dict[str, Any]] | None:
        """List registered server-side threat detectors and versions."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/threat-detection/detectors",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch detectors: %s", exc)
            return None

    # ── Controlled Execution Gateway (Phase 6) ──────────────────────────────

    def execute_tool(
        self,
        agent_id: str,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any] | None:
        """Submit a tool execution through the Controlled Execution Gateway."""
        try:
            payload = {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "action_name": action_name,
                "arguments": arguments,
                "idempotency_key": idempotency_key,
            }
            resp = self._client.post(
                f"{self.api_prefix}/executions",
                json=payload,
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Tool execution request failed: %s", exc)
            return None

    def list_executions(
        self,
        agent_id: str | None = None,
        tool_name: str | None = None,
        status: str | None = None,
        decision: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> dict[str, Any] | None:
        """Fetch historical tool execution records."""
        try:
            params = [f"page={page}", f"size={size}"]
            if agent_id:
                params.append(f"agent_id={agent_id}")
            if tool_name:
                params.append(f"tool_name={tool_name}")
            if status:
                params.append(f"status={status}")
            if decision:
                params.append(f"decision={decision}")
            qs = "&".join(params)
            resp = self._client.get(
                f"{self.api_prefix}/executions?{qs}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch executions: %s", exc)
            return None

    def get_execution(self, execution_id: str) -> dict[str, Any] | None:
        """Fetch details of a single execution."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/executions/{execution_id}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to fetch execution %s: %s", execution_id, exc)
            return None

    def approve_execution(self, execution_id: str, notes: str | None = None) -> dict[str, Any] | None:
        """Approve a pending tool execution using human supervisor credentials."""
        try:
            payload = {"approval_notes": notes} if notes else {}
            resp = self._client.post(
                f"{self.api_prefix}/executions/{execution_id}/approve",
                json=payload,
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to approve execution %s: %s", execution_id, exc)
            return None

    def cancel_execution(self, execution_id: str) -> dict[str, Any] | None:
        """Cancel a pending tool execution."""
        try:
            resp = self._client.post(
                f"{self.api_prefix}/executions/{execution_id}/cancel",
                json={},
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to cancel execution %s: %s", execution_id, exc)
            return None

    def list_tools(self) -> list[dict[str, Any]] | None:
        """List registered tools from the Controlled Tool Registry."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/tools",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to list tools: %s", exc)
            return None

    def get_tool(self, tool_name: str) -> dict[str, Any] | None:
        """Get tool definition metadata."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/tools/{tool_name}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as exc:
            logger.warning("Failed to get tool %s: %s", tool_name, exc)
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
