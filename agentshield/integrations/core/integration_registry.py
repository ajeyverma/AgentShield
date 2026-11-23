"""
AgentShield AI — Framework Integration Registry (Phase 9).
"""

from __future__ import annotations

import logging
from typing import Type

from agentshield.contracts.enums import IntegrationType
from agentshield.integrations.core.base_adapter import BaseFrameworkAdapter
from agentshield.integrations.core.integration_config import AgentShieldIntegrationConfig

logger = logging.getLogger("agentshield.integrations.core.registry")


class IntegrationRegistry:
    """Registry managing available and active AI agent framework adapters."""

    def __init__(self) -> None:
        self._adapter_classes: dict[IntegrationType, Type[BaseFrameworkAdapter]] = {}
        self._active_adapters: dict[str, BaseFrameworkAdapter] = {}

    def register_adapter_class(
        self,
        framework_type: IntegrationType,
        adapter_cls: Type[BaseFrameworkAdapter],
    ) -> None:
        """Register an adapter class for a framework type."""
        self._adapter_classes[framework_type] = adapter_cls
        logger.debug("Registered integration adapter class for %s", framework_type.value)

    def get_adapter_class(self, framework_type: IntegrationType) -> Type[BaseFrameworkAdapter] | None:
        """Retrieve adapter class by framework type."""
        return self._adapter_classes.get(framework_type)

    def create_adapter(
        self,
        framework_type: IntegrationType,
        config: AgentShieldIntegrationConfig,
    ) -> BaseFrameworkAdapter:
        """Instantiate and register an active framework adapter."""
        cls = self._adapter_classes.get(framework_type)
        if not cls:
            raise ValueError(f"No integration adapter registered for framework: {framework_type.value}")
        adapter = cls(config)
        adapter.initialize()
        self._active_adapters[config.agent_id] = adapter
        return adapter

    def get_active_adapter(self, agent_id: str) -> BaseFrameworkAdapter | None:
        """Retrieve active adapter instance by agent_id."""
        return self._active_adapters.get(agent_id)

    def list_supported_frameworks(self) -> list[IntegrationType]:
        """List all supported framework integration types."""
        return list(self._adapter_classes.keys())


# Global singleton registry
integration_registry = IntegrationRegistry()
