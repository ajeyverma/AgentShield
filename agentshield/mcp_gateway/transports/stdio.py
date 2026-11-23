"""
AgentShield AI — Safe STDIO Transport for MCP (Phase 8).
"""

from __future__ import annotations

import asyncio
import os
import shutil
from typing import Any

from agentshield.mcp_gateway.configuration import MCPGatewayConfig, default_mcp_gateway_config
from agentshield.mcp_gateway.exceptions import MCPTransportError, MCPUntrustedCommandError


class StdioTransportManager:
    """
    Manages secure STDIO subprocess lifecycles for upstream MCP servers.
    Enforces executable whitelisting, prevents arbitrary shell commands,
    and isolates child process environment variables.
    """

    def __init__(self, config: MCPGatewayConfig | None = None) -> None:
        self.config = config or default_mcp_gateway_config

    def resolve_executable(self, command: str) -> str:
        """Resolve executable path and verify against whitelist."""
        if not self.config.is_executable_allowed(command):
            raise MCPUntrustedCommandError(command)

        # Find full path
        resolved = shutil.which(command)
        if not resolved:
            # If absolute or relative path provided, check if it exists
            if os.path.exists(command):
                resolved = command
            else:
                raise MCPTransportError(f"Executable '{command}' not found on host system.")
        return resolved

    def build_safe_environment(self, custom_env: dict[str, str] | None = None) -> dict[str, str]:
        """
        Build a sanitized environment for subprocess, inheriting safe system variables
        while stripping sensitive AgentShield host secrets.
        """
        # Base system environment
        safe_keys = {
            "PATH",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "LANG",
            "LC_ALL",
            "NODE_PATH",
            "PYTHONPATH",
        }
        env: dict[str, str] = {}
        for k, v in os.environ.items():
            if k.upper() in safe_keys:
                env[k] = v

        # Add custom server-specific variables (reject any internal AgentShield keys)
        if custom_env:
            for k, v in custom_env.items():
                if not k.upper().startswith("AGENTSHIELD_"):
                    env[k] = str(v)

        return env
