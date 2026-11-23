"""
AgentShield AI — AgentShield Client for OpenAI Agents SDK (Phase 7).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import httpx

from agentshield.integrations.openai_agents.configuration import AgentShieldIntegrationConfig
from agentshield.integrations.openai_agents.exceptions import (
    AuthenticationFailureError,
    BackendUnavailableError,
    OpenAIIntegrationError,
    redact_secrets,
)
from agentshield.integrations.openai_agents.schemas import AgentShieldToolResult

logger = logging.getLogger("agentshield.integrations.openai_agents.client")


class AgentShieldOpenAIClient:
    """Authenticated HTTP client that connects the OpenAI SDK adapter to AgentShield."""

    def __init__(self, config: AgentShieldIntegrationConfig) -> None:
        self.config = config
        self.base_url = f"{config.backend_url.rstrip('/')}{config.api_prefix}"
        self._headers = {
            "Content-Type": "application/json",
            "X-Agent-Credential": config.agent_credential,
        }

    def _format_error_result(self, error_code: str, message: str) -> AgentShieldToolResult:
        return AgentShieldToolResult(
            status="BLOCKED" if self.config.fail_closed else "FAILED",
            decision="BLOCK",
            error_code=error_code,
            error_message=redact_secrets(message),
        )

    async def authenticate_async(self) -> dict[str, Any]:
        """Authenticate agent credentials asynchronously against the AgentShield backend."""
        url = f"{self.base_url}/agents/authenticate"
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                resp = await client.post(url, json={"credential": self.config.agent_credential})
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 401:
                    raise AuthenticationFailureError("Invalid AgentShield agent credential.")
                else:
                    raise OpenAIIntegrationError(f"Backend returned HTTP {resp.status_code}: {resp.text}")
        except httpx.ConnectError as exc:
            if self.config.fail_closed:
                raise BackendUnavailableError(f"Cannot connect to AgentShield backend at {self.base_url}") from exc
            raise

    def authenticate(self) -> dict[str, Any]:
        """Synchronously authenticate agent credentials against AgentShield."""
        url = f"{self.base_url}/agents/authenticate"
        try:
            with httpx.Client(timeout=self.config.timeout_seconds) as client:
                resp = client.post(url, json={"credential": self.config.agent_credential})
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 401:
                    raise AuthenticationFailureError("Invalid AgentShield agent credential.")
                else:
                    raise OpenAIIntegrationError(f"Backend returned HTTP {resp.status_code}: {resp.text}")
        except httpx.ConnectError as exc:
            if self.config.fail_closed:
                raise BackendUnavailableError(f"Cannot connect to AgentShield backend at {self.base_url}") from exc
            raise

    async def execute_tool_async(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> AgentShieldToolResult:
        """Submit tool execution asynchronously to the AgentShield Gateway."""
        url = f"{self.base_url}/executions"
        payload = {
            "agent_id": self.config.agent_id,
            "tool_name": tool_name,
            "action_name": action_name,
            "arguments": arguments,
            "idempotency_key": idempotency_key or f"sdk-{uuid.uuid4()}",
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                resp = await client.post(url, json=payload, headers=self._headers)
                return self._parse_execution_response(resp)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            logger.error("AgentShield backend connection failure: %s", redact_secrets(str(exc)))
            if self.config.fail_closed:
                return self._format_error_result("BACKEND_UNAVAILABLE", "AgentShield backend gateway is unreachable. Action denied fail-closed.")
            raise BackendUnavailableError() from exc

    def execute_tool(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> AgentShieldToolResult:
        """Submit tool execution synchronously to the AgentShield Gateway."""
        url = f"{self.base_url}/executions"
        payload = {
            "agent_id": self.config.agent_id,
            "tool_name": tool_name,
            "action_name": action_name,
            "arguments": arguments,
            "idempotency_key": idempotency_key or f"sdk-{uuid.uuid4()}",
        }

        try:
            with httpx.Client(timeout=self.config.timeout_seconds) as client:
                resp = client.post(url, json=payload, headers=self._headers)
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
                execution_id=str(data.get("execution_id")),
                approval_id=str(data.get("approval_id")) if data.get("approval_id") else None,
                result=data.get("result"),
                error_code=data.get("error_code"),
                error_message=data.get("error_message"),
            )
        elif resp.status_code == 401:
            return self._format_error_result("AUTHENTICATION_FAILED", "Agent authentication failed on AgentShield gateway.")
        elif resp.status_code == 403:
            return self._format_error_result("FORBIDDEN", resp.json().get("detail", "Access denied by AgentShield gateway."))
        elif resp.status_code == 404:
            return self._format_error_result("TOOL_NOT_FOUND", resp.json().get("detail", "Tool or agent not found on gateway."))
        elif resp.status_code == 409:
            return self._format_error_result("IDEMPOTENCY_CONFLICT", resp.json().get("detail", "Idempotency conflict on gateway."))
        else:
            return self._format_error_result("GATEWAY_ERROR", f"AgentShield gateway returned HTTP {resp.status_code}: {resp.text}")
