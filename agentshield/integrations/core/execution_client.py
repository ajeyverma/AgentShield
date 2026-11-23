"""
AgentShield AI — Shared Execution Client (Phase 9).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any
import httpx

from agentshield.integrations.core.exceptions import (
    AuthenticationFailureError,
    BackendUnavailableError,
    IntegrationError,
    redact_secrets,
)
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.result_handler import AgentShieldToolResult

logger = logging.getLogger("agentshield.integrations.core.execution_client")


class AgentShieldExecutionClient:
    """
    Universal HTTP client mediating AI agent tool calls to the AgentShield
    Controlled Tool Execution Gateway.
    """

    def __init__(self, config: AgentShieldIntegrationConfig) -> None:
        self.config = config
        self.base_url = f"{config.backend_url.rstrip('/')}{config.api_prefix}"
        self._headers = {
            "Content-Type": "application/json",
            "X-Agent-Credential": config.agent_credential,
        }
        if config.custom_headers:
            self._headers.update(config.custom_headers)

    def _format_error_result(self, error_code: str, message: str) -> AgentShieldToolResult:
        return AgentShieldToolResult(
            status="BLOCKED" if self.config.fail_closed else "FAILED",
            decision="BLOCK",
            error_code=error_code,
            error_message=redact_secrets(message),
        )

    def _simulate_tool_execution(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
    ) -> AgentShieldToolResult:
        """Simulate realistic security engine & gateway execution for demos/tests."""
        # Check for traversal attack in file system tools
        if tool_name == "sandbox_fs":
            path = str(arguments.get("path", ""))
            if ".." in path or path.startswith("/") or path.startswith("\\"):
                return AgentShieldToolResult(
                    status="BLOCKED",
                    decision="BLOCK",
                    error_code="PATH_TRAVERSAL_DETECTED",
                    error_message="Security Policy Violation: Path traversal attack attempt blocked by AgentShield.",
                )
            if action_name == "write_file":
                return AgentShieldToolResult(
                    status="COMPLETED",
                    decision="ALLOW",
                    execution_id=f"exec-{uuid.uuid4().hex[:8]}",
                    result={"path": path, "bytes_written": len(str(arguments.get("content", ""))), "status": "created"},
                )
            elif action_name == "read_file":
                return AgentShieldToolResult(
                    status="COMPLETED",
                    decision="ALLOW",
                    execution_id=f"exec-{uuid.uuid4().hex[:8]}",
                    result={"path": path, "content": "Simulated file content from sandbox."},
                )

        # Calculator
        elif tool_name == "calculator":
            a = float(arguments.get("a", 0))
            b = float(arguments.get("b", 0))
            if action_name == "add":
                res = a + b
            elif action_name == "subtract":
                res = a - b
            elif action_name == "multiply":
                res = a * b
            elif action_name == "divide":
                res = a / b if b != 0 else float("inf")
            else:
                res = a + b
            return AgentShieldToolResult(
                status="COMPLETED",
                decision="ALLOW",
                execution_id=f"exec-{uuid.uuid4().hex[:8]}",
                result=res,
            )

        # Mock Email - sensitive, triggers ASK_HUMAN
        elif tool_name == "mock_email":
            if approval_id:
                return AgentShieldToolResult(
                    status="COMPLETED",
                    decision="ALLOW",
                    execution_id=f"exec-{uuid.uuid4().hex[:8]}",
                    approval_id=approval_id,
                    result={"status": "sent", "recipient": arguments.get("recipient")},
                )
            return AgentShieldToolResult(
                status="PENDING_APPROVAL",
                decision="ASK_HUMAN",
                approval_id=f"appr-{uuid.uuid4().hex[:8]}",
                error_message="Action requires human security authorization. Approval request has been generated.",
            )

        # Default fallback
        return AgentShieldToolResult(
            status="COMPLETED",
            decision="ALLOW",
            execution_id=f"exec-{uuid.uuid4().hex[:8]}",
            result={"status": "simulated_ok"},
        )

    def authenticate(self) -> dict[str, Any]:
        """Synchronously verify agent credentials against the AgentShield backend."""
        if self.config.backend_url.startswith("simulate://"):
            return {"authenticated": True, "agent_id": self.config.agent_id}

        url = f"{self.base_url}/agents/authenticate"
        try:
            with httpx.Client(timeout=self.config.timeout_seconds) as client:
                resp = client.post(url, json={"credential": self.config.agent_credential})
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 401:
                    raise AuthenticationFailureError("Invalid AgentShield agent credential.")
                else:
                    raise IntegrationError(f"Backend returned HTTP {resp.status_code}: {resp.text}")
        except httpx.ConnectError as exc:
            if self.config.fail_closed:
                raise BackendUnavailableError(f"Cannot connect to AgentShield backend at {self.base_url}") from exc
            raise

    async def authenticate_async(self) -> dict[str, Any]:
        """Asynchronously verify agent credentials against the AgentShield backend."""
        if self.config.backend_url.startswith("simulate://"):
            return {"authenticated": True, "agent_id": self.config.agent_id}

        url = f"{self.base_url}/agents/authenticate"
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                resp = await client.post(url, json={"credential": self.config.agent_credential})
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 401:
                    raise AuthenticationFailureError("Invalid AgentShield agent credential.")
                else:
                    raise IntegrationError(f"Backend returned HTTP {resp.status_code}: {resp.text}")
        except httpx.ConnectError as exc:
            if self.config.fail_closed:
                raise BackendUnavailableError(f"Cannot connect to AgentShield backend at {self.base_url}") from exc
            raise

    def execute_tool(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
        approval_id: str | None = None,
    ) -> AgentShieldToolResult:
        """Submit tool execution synchronously to the AgentShield Controlled Execution Gateway."""
        if self.config.backend_url.startswith("simulate://"):
            return self._simulate_tool_execution(tool_name, action_name, arguments, approval_id)

        url = f"{self.base_url}/executions"
        payload = {
            "agent_id": self.config.agent_id,
            "tool_name": tool_name,
            "action_name": action_name,
            "arguments": arguments,
            "idempotency_key": idempotency_key or f"sdk-{uuid.uuid4()}",
        }
        if approval_id:
            payload["approval_id"] = approval_id

        try:
            with httpx.Client(timeout=self.config.timeout_seconds) as client:
                resp = client.post(url, json=payload, headers=self._headers)
                return self._parse_execution_response(resp)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            logger.error("AgentShield backend connection failure: %s", redact_secrets(str(exc)))
            if self.config.fail_closed:
                return self._format_error_result("BACKEND_UNAVAILABLE", "AgentShield backend gateway is unreachable. Action denied fail-closed.")
            raise BackendUnavailableError() from exc

    async def execute_tool_async(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
        approval_id: str | None = None,
    ) -> AgentShieldToolResult:
        """Submit tool execution asynchronously to the AgentShield Controlled Execution Gateway."""
        if self.config.backend_url.startswith("simulate://"):
            return self._simulate_tool_execution(tool_name, action_name, arguments, approval_id)

        url = f"{self.base_url}/executions"
        payload = {
            "agent_id": self.config.agent_id,
            "tool_name": tool_name,
            "action_name": action_name,
            "arguments": arguments,
            "idempotency_key": idempotency_key or f"sdk-{uuid.uuid4()}",
        }
        if approval_id:
            payload["approval_id"] = approval_id

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                resp = await client.post(url, json=payload, headers=self._headers)
                return self._parse_execution_response(resp)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            logger.error("AgentShield backend connection failure: %s", redact_secrets(str(exc)))
            if self.config.fail_closed:
                return self._format_error_result("BACKEND_UNAVAILABLE", "AgentShield backend gateway is unreachable. Action denied fail-closed.")
            raise BackendUnavailableError() from exc

    def _parse_execution_response(self, resp: httpx.Response) -> AgentShieldToolResult:
        if resp.status_code == 200:
            data = resp.json()
            return AgentShieldToolResult(
                status=data.get("status", "COMPLETED"),
                decision=data.get("decision", "BLOCK"),
                execution_id=str(data.get("execution_id")) if data.get("execution_id") else None,
                approval_id=str(data.get("approval_id")) if data.get("approval_id") else None,
                result=data.get("result"),
                error_code=data.get("error_code"),
                error_message=data.get("error_message"),
            )
        elif resp.status_code == 403:
            data = resp.json()
            return AgentShieldToolResult(
                status="BLOCKED",
                decision="BLOCK",
                execution_id=str(data.get("execution_id")) if data.get("execution_id") else None,
                error_code="SECURITY_POLICY_BLOCKED",
                error_message=data.get("detail", "Operation blocked by AgentShield security policies."),
            )
        elif resp.status_code == 401:
            raise AuthenticationFailureError("Invalid AgentShield agent credential.")
        else:
            return self._format_error_result("HTTP_ERROR", f"Backend error HTTP {resp.status_code}: {resp.text}")
