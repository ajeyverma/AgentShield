"""
AgentShield AI — Integration Interfaces.

Defines abstract base classes (ABCs) and Protocol definitions for all
planned integration channels.  These interfaces ensure that SDK adapters,
MCP proxies, and custom agent connectors all present a uniform surface to
the AgentShield security core.

Nothing here connects to real AI providers or MCP servers.  Concrete
implementations are delivered in Phase 4+ (SDK integrations) and
Phase 5+ (MCP proxy).

Design principles
─────────────────
1. Every integration path maps its native tool-call format to the shared
   ActionRequest contract before submitting it to the backend.
2. Every integration path obeys the SecurityDecision returned by the backend
   without modification.
3. The integration layer MUST enforce fail-closed behavior: if the backend is
   unreachable, the default action is BLOCK (deny), never ALLOW.
4. The execution gateway (ControlledExecutor) validates a backend-issued
   authorization token before invoking any tool.  Clients cannot bypass
   security evaluation by calling the executor directly with a forged ALLOW.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.decision import SecurityDecision
from agentshield.contracts.enums import IntegrationType


# ---------------------------------------------------------------------------
# Base integration adapter
# ---------------------------------------------------------------------------


class BaseIntegrationAdapter(ABC):
    """Abstract base for all AgentShield integration adapters.

    An integration adapter is responsible for:
      1. Intercepting tool execution requests from a specific AI framework.
      2. Mapping the framework-native call format to an ActionRequest.
      3. Submitting the ActionRequest to the AgentShield backend.
      4. Receiving and enforcing the SecurityDecision.
      5. Forwarding the tool call to the ControlledExecutor only on ALLOW.

    Subclasses MUST implement:
        integration_type  — The IntegrationType enum value for this adapter.
        normalize_request — Maps a framework-native call to an ActionRequest.
        handle_decision   — Acts on the SecurityDecision (ALLOW/BLOCK/ASK_HUMAN).
    """

    @property
    @abstractmethod
    def integration_type(self) -> IntegrationType:
        """The integration channel this adapter represents."""

    @abstractmethod
    async def normalize_request(
        self,
        native_tool_call: Any,
        *,
        tenant_id: str,
        agent_id: str,
        session_id: str | None = None,
    ) -> ActionRequest:
        """Map a framework-native tool call to a normalized ActionRequest.

        Args:
            native_tool_call: The raw tool-call object from the AI framework.
            tenant_id: Server-verified tenant identifier (NOT from the agent).
            agent_id:  Registered agent identifier (NOT from the agent).
            session_id: Backend-issued session identifier.

        Returns:
            A fully populated ActionRequest ready for security evaluation.
        """

    @abstractmethod
    async def handle_decision(
        self,
        decision: SecurityDecision,
        original_request: ActionRequest,
    ) -> Any:
        """Act on a SecurityDecision received from the backend.

        Args:
            decision:         The SecurityDecision from the backend.
            original_request: The ActionRequest that produced this decision.

        Returns:
            The result to return to the AI agent (tool output or error).

        Behavior contract:
            ALLOW     → Forward the tool call to the ControlledExecutor.
            BLOCK     → Raise an exception or return a structured error to the agent.
            ASK_HUMAN → Suspend execution and await approval resolution.
        """


# ---------------------------------------------------------------------------
# SDK/API adapter
# ---------------------------------------------------------------------------


class BaseSDKAdapter(BaseIntegrationAdapter, ABC):
    """Abstract base for SDK-based integrations.

    SDK adapters intercept tool calls within the AI framework's execution
    loop (e.g. OpenAI Agents function hooks, LangGraph ToolNode wrappers).

    Additional responsibilities specific to SDK adapters:
        - Register the agent with the backend at session start.
        - Report session end to the backend.
        - Propagate agent context (framework, version) in SourceContext.
    """

    @abstractmethod
    async def on_session_start(self, agent_id: str, tenant_id: str) -> str:
        """Called when an agent session begins.

        Returns:
            Backend-issued session_id to attach to all subsequent requests.
        """

    @abstractmethod
    async def on_session_end(self, session_id: str) -> None:
        """Called when an agent session ends (normally or on error)."""


# ---------------------------------------------------------------------------
# MCP adapter
# ---------------------------------------------------------------------------


class BaseMCPAdapter(BaseIntegrationAdapter, ABC):
    """Abstract base for MCP (Model Context Protocol) integrations.

    The MCP adapter acts as a transparent proxy between MCP-compatible
    clients and the actual MCP tool servers.  Every MCP tool call is
    intercepted, normalized to an ActionRequest, evaluated by the backend,
    and only forwarded to the real MCP server on an ALLOW decision.

    Design note: The MCP adapter does not expose the upstream MCP server
    address to clients.  Clients connect to the AgentShield MCP proxy, not
    directly to the tool server.
    """

    @abstractmethod
    async def proxy_tool_call(
        self,
        mcp_tool_call: dict[str, Any],
        *,
        tenant_id: str,
        agent_id: str,
    ) -> dict[str, Any]:
        """Intercept an MCP tool call, evaluate it, and conditionally proxy it.

        Args:
            mcp_tool_call: Raw MCP tool call message.
            tenant_id:     Server-verified tenant identifier.
            agent_id:      Registered agent identifier.

        Returns:
            MCP tool result (from the real server on ALLOW, or an error response).
        """


# ---------------------------------------------------------------------------
# Controlled executor
# ---------------------------------------------------------------------------


class BaseControlledExecutor(ABC):
    """Abstract base for the controlled tool execution gateway.

    The executor is the ONLY component permitted to invoke real tools.
    It enforces that every execution request is backed by a backend-issued
    authorization token (the decision_id from an ALLOW SecurityDecision).

    This prevents clients from bypassing security evaluation by calling
    the executor directly.
    """

    @abstractmethod
    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        authorization_token: str,
    ) -> Any:
        """Execute an authorized tool call.

        Args:
            tool_name:           Name of the tool to invoke.
            arguments:           Validated arguments for the tool.
            authorization_token: Backend-issued token proving an ALLOW decision
                                 was made for this specific request.  MUST be
                                 verified before execution proceeds.

        Returns:
            The tool's execution result.

        Raises:
            ExecutionForgeryError: If the authorization_token is invalid or absent.
            ExecutionError:        If the tool call fails after authorization.
        """


# ---------------------------------------------------------------------------
# Agent connector registry (placeholder for Phase 4+)
# ---------------------------------------------------------------------------


class AgentConnectorRegistry:
    """Registry of registered integration adapters.

    In Phase 4+ this will be populated at backend startup by scanning
    installed integration packages.  Connectors are keyed by IntegrationType.
    """

    def __init__(self) -> None:
        self._adapters: dict[IntegrationType, BaseIntegrationAdapter] = {}

    def register(self, adapter: BaseIntegrationAdapter) -> None:
        """Register an integration adapter."""
        self._adapters[adapter.integration_type] = adapter

    def get(self, integration_type: IntegrationType) -> BaseIntegrationAdapter | None:
        """Retrieve a registered adapter by integration type."""
        return self._adapters.get(integration_type)

    def list_registered(self) -> list[IntegrationType]:
        """Return a list of all registered integration types."""
        return list(self._adapters.keys())
