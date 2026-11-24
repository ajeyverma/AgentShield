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

    def ensure_authenticated(self) -> bool:
        """Ensure desktop client has an active session token with backend."""
        if self.token:
            return True
        # Try logging in with default desktop user
        if self.login("admin", "Admin12345!"):
            return True
        # If user not created yet in clean database, register default desktop admin user
        self.register("admin@agentshield.io", "admin", "Admin12345!")
        return self.login("admin", "Admin12345!")

    def _headers(self) -> dict[str, str]:
        if not self.token:
            self.ensure_authenticated()
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
                if not self.token:
                    self.ensure_authenticated()
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

    def get_approvals(self, status: str | None = None, search: str | None = None, page: int = 1, size: int = 50) -> list[dict[str, Any]] | None:
        try:
            params: dict[str, Any] = {"page": page, "size": size}
            if status:
                params["status"] = status
            if search:
                params["search"] = search
            resp = self._client.get(
                f"{self.api_prefix}/approvals",
                headers=self._headers(),
                params=params,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch approvals: %s", exc)
            return None

    def get_approval_detail(self, approval_id: str) -> dict[str, Any] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/approvals/{approval_id}",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to get approval detail: %s", exc)
            return None

    def approve_request(self, approval_id: str, comment: str | None = None) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/approvals/{approval_id}/approve",
                headers=self._headers(),
                json={"comment": comment},
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to approve request: %s", exc)
            return None

    def reject_request(self, approval_id: str, reason: str) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/approvals/{approval_id}/reject",
                headers=self._headers(),
                json={"reason": reason},
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to reject request: %s", exc)
            return None

    def cancel_approval_request(self, approval_id: str, reason: str | None = None) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/approvals/{approval_id}/cancel",
                headers=self._headers(),
                json={"reason": reason},
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to cancel approval request: %s", exc)
            return None

    def get_approval_history(self, approval_id: str) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/approvals/{approval_id}/history",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to get approval history: %s", exc)
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

    def get_policies(self, category: str | None = None, is_enabled: bool | None = None) -> list[dict[str, Any]] | None:
        try:
            params = {}
            if category:
                params["category"] = category
            if is_enabled is not None:
                params["is_enabled"] = is_enabled
            resp = self._client.get(
                f"{self.api_prefix}/policies",
                headers=self._headers(),
                params=params,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch policies: %s", exc)
            return None

    def create_policy(self, data: dict[str, Any]) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/policies",
                headers=self._headers(),
                json=data,
            )
            return resp.json() if resp.status_code == 201 else None
        except Exception as exc:
            logger.warning("Failed to create policy: %s", exc)
            return None

    def update_policy(self, policy_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        try:
            resp = self._client.patch(
                f"{self.api_prefix}/policies/{policy_id}",
                headers=self._headers(),
                json=data,
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to update policy: %s", exc)
            return None

    def enable_policy(self, policy_id: str) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/policies/{policy_id}/enable",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to enable policy: %s", exc)
            return None

    def disable_policy(self, policy_id: str) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/policies/{policy_id}/disable",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to disable policy: %s", exc)
            return None

    def duplicate_policy(self, policy_id: str) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/policies/{policy_id}/duplicate",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 201 else None
        except Exception as exc:
            logger.warning("Failed to duplicate policy: %s", exc)
            return None

    def delete_policy(self, policy_id: str) -> bool:
        try:
            resp = self._client.delete(
                f"{self.api_prefix}/policies/{policy_id}",
                headers=self._headers(),
            )
            return resp.status_code == 204
        except Exception as exc:
            logger.warning("Failed to delete policy: %s", exc)
            return False

    def get_policy_history(self, policy_id: str) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/policies/{policy_id}/history",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to get policy history: %s", exc)
            return None

    def get_policy_conflicts(self) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/policies/conflicts",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to get policy conflicts: %s", exc)
            return None

    def simulate_policy(self, sim_data: dict[str, Any]) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/policies/simulate",
                headers=self._headers(),
                json=sim_data,
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to simulate policy: %s", exc)
            return None

    # ── Emergency Security Controls (Phase 10) ───────────────────────────────

    def get_emergency_status(self) -> dict[str, Any] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/security/emergency-status",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to get emergency status: %s", exc)
            return None

    def list_emergency_controls(self, active_only: bool = False) -> list[dict[str, Any]] | None:
        try:
            resp = self._client.get(
                f"{self.api_prefix}/security/emergency-controls",
                headers=self._headers(),
                params={"active_only": active_only},
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to list emergency controls: %s", exc)
            return None

    def activate_emergency_control(self, control_type: str, target_identifier: str, reason: str) -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/security/emergency-controls",
                headers=self._headers(),
                json={
                    "control_type": control_type,
                    "target_identifier": target_identifier,
                    "reason": reason,
                },
            )
            return resp.json() if resp.status_code == 201 else None
        except Exception as exc:
            logger.warning("Failed to activate emergency control: %s", exc)
            return None

    def revoke_emergency_control(self, control_id: str, reason: str = "Revoked by admin") -> dict[str, Any] | None:
        try:
            resp = self._client.post(
                f"{self.api_prefix}/security/emergency-controls/{control_id}/revoke",
                headers=self._headers(),
                json={"reason": reason},
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to revoke emergency control: %s", exc)
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

    # ── Phase 11: Monitoring, Alerts, Incidents & Tamper-Evident Audit ────────

    def get_security_events(
        self,
        page: int = 1,
        size: int = 50,
        event_type: str | None = None,
        severity: str | None = None,
        component: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch paginated security events."""
        try:
            params: dict[str, Any] = {"page": page, "size": size}
            if event_type:
                params["event_type"] = event_type
            if severity:
                params["severity"] = severity
            if component:
                params["component"] = component
            if agent_id:
                params["agent_id"] = agent_id

            resp = self._client.get(
                f"{self.api_prefix}/events",
                headers=self._headers(),
                params=params,
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to fetch security events: %s", exc)
            return None

    def get_alerts(self, status: str | None = None, severity: str | None = None) -> list[dict[str, Any]] | None:
        """Fetch active or historical security alerts."""
        try:
            params = {}
            if status:
                params["status"] = status
            if severity:
                params["severity"] = severity
            resp = self._client.get(
                f"{self.api_prefix}/alerts",
                headers=self._headers(),
                params=params,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to fetch alerts: %s", exc)
            return None

    def update_alert_status(self, alert_id: str, new_status: str) -> dict[str, Any] | None:
        """Update alert status (active/acknowledged/resolved/suppressed)."""
        try:
            resp = self._client.patch(
                f"{self.api_prefix}/alerts/{alert_id}/status",
                headers=self._headers(),
                json={"status": new_status},
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to update alert %s: %s", alert_id, exc)
            return None

    def list_incidents(self, status: str | None = None) -> list[dict[str, Any]] | None:
        """List security incidents."""
        try:
            params = {}
            if status:
                params["status"] = status
            resp = self._client.get(
                f"{self.api_prefix}/incidents",
                headers=self._headers(),
                params=params,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("items", []) if isinstance(data, dict) else data
            return None
        except Exception as exc:
            logger.warning("Failed to list incidents: %s", exc)
            return None

    def create_incident(self, title: str, description: str, severity: str = "MEDIUM", alert_id: str | None = None) -> dict[str, Any] | None:
        """Open a new security incident."""
        try:
            resp = self._client.post(
                f"{self.api_prefix}/incidents",
                headers=self._headers(),
                json={"title": title, "description": description, "severity": severity, "alert_id": alert_id},
            )
            return resp.json() if resp.status_code == 201 else None
        except Exception as exc:
            logger.warning("Failed to create incident: %s", exc)
            return None

    def get_metrics_summary(self) -> dict[str, Any] | None:
        """Fetch aggregated metrics counters, gauges, and latency percentiles."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/metrics/summary",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to get metrics summary: %s", exc)
            return None

    def get_system_health(self) -> dict[str, Any] | None:
        """Fetch system health and cryptographic audit chain validity."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/metrics/health",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to get system health: %s", exc)
            return None

    def verify_audit_chain(self) -> dict[str, Any] | None:
        """Cryptographically verify the tamper-evident hash chain."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/audit-logs/verify",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to verify audit chain: %s", exc)
            return None

    def export_audit_trail(self) -> dict[str, Any] | None:
        """Export verifiable audit trail."""
        try:
            resp = self._client.get(
                f"{self.api_prefix}/audit-logs/export",
                headers=self._headers(),
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.warning("Failed to export audit trail: %s", exc)
            return None


# Module-level default instance
backend_client = BackendClient()
