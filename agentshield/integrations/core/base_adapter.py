"""
AgentShield AI — Base Framework Adapter Interface (Phase 9).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.execution_client import AgentShieldExecutionClient
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig
from agentshield.integrations.core.result_handler import AgentShieldToolResult


class BaseFrameworkAdapter(ABC):
    """
    Common contract implemented by every AI agent framework adapter.
    Normalizes security boundaries, identity resolution, tool exposure,
    and gateway execution across disparate framework paradigms.
    """

    def __init__(self, config: AgentShieldIntegrationConfig) -> None:
        self.config = config
        self.client = AgentShieldExecutionClient(config)
        self._is_initialized: bool = False

    @property
    @abstractmethod
    def framework_type(self) -> IntegrationType:
        """The specific integration framework type."""

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Human-readable framework name."""

    @property
    def is_initialized(self) -> bool:
        return self._is_initialized

    def initialize(self) -> None:
        """Initialize adapter state and verify configuration."""
        self._is_initialized = True

    @abstractmethod
    def get_wrapped_tools(self) -> list[Any]:
        """Return framework-compatible wrapped tools for only permitted allowlisted tools."""

    @abstractmethod
    def execute_tool(
        self,
        tool_name: str,
        action_name: str,
        arguments: dict[str, Any],
        approval_id: str | None = None,
    ) -> AgentShieldToolResult:
        """Execute a tool call through AgentShield."""

    def health_check(self) -> bool:
        """Verify connectivity to AgentShield backend."""
        try:
            self.client.authenticate()
            return True
        except Exception:
            return False

    def shutdown(self) -> None:
        """Clean up integration resources."""
        self._is_initialized = False
