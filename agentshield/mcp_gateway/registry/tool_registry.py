"""
AgentShield AI — MCP Tool Registry & Namespacing (Phase 8).
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field


class DiscoveredTool(BaseModel):
    """Normalized MCP tool with namespaced identifier and provenance."""

    namespaced_name: str
    original_name: str
    server_id: str
    server_name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    is_safe: bool = True
    security_tags: list[str] = Field(default_factory=list)


class MCPToolRegistry:
    """
    Manages MCP tool registration, collision resolution, and namespacing.
    Converts tools discovered from external servers into qualified names:
    `<server_prefix>_<original_tool_name>`.
    """

    def __init__(self) -> None:
        # namespaced_name -> DiscoveredTool
        self._tools: dict[str, DiscoveredTool] = {}
        # (server_id, original_name) -> namespaced_name
        self._lookup: dict[tuple[str, str], str] = {}

    @staticmethod
    def sanitize_prefix(server_name: str) -> str:
        """Sanitize server name for use as a tool namespace prefix."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", server_name).lower()
        return clean.strip("_") or "mcp"

    def register_tool(
        self,
        server_id: str,
        server_name: str,
        original_name: str,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
    ) -> DiscoveredTool:
        """
        Register a tool discovered from an upstream MCP server.
        Generates namespaced name: `<server_prefix>_<original_name>`.
        Handles collisions deterministically.
        """
        prefix = self.sanitize_prefix(server_name)
        base_name = f"{prefix}_{original_name}"
        namespaced_name = base_name

        # If already registered for THIS exact server and tool, update it
        key = (server_id, original_name)
        if key in self._lookup:
            namespaced_name = self._lookup[key]
        else:
            # Check for collisions with other servers
            counter = 1
            while namespaced_name in self._tools and self._tools[namespaced_name].server_id != server_id:
                namespaced_name = f"{base_name}_{counter}"
                counter += 1

        tool = DiscoveredTool(
            namespaced_name=namespaced_name,
            original_name=original_name,
            server_id=server_id,
            server_name=server_name,
            description=description,
            input_schema=input_schema or {},
        )
        self._tools[namespaced_name] = tool
        self._lookup[key] = namespaced_name
        return tool

    def get_tool(self, namespaced_or_raw: str, server_id: str | None = None) -> DiscoveredTool | None:
        """Find a tool by namespaced name or (server_id, raw_name)."""
        if namespaced_or_raw in self._tools:
            return self._tools[namespaced_or_raw]

        if server_id:
            key = (server_id, namespaced_or_raw)
            if key in self._lookup:
                return self._tools[self._lookup[key]]

        # Fallback search by raw original name if unique
        matching = [t for t in self._tools.values() if t.original_name == namespaced_or_raw]
        if len(matching) == 1:
            return matching[0]

        return None

    def list_tools(self, server_id: str | None = None) -> list[DiscoveredTool]:
        """List registered tools, optionally filtered by server_id."""
        if server_id:
            return [t for t in self._tools.values() if t.server_id == server_id]
        return list(self._tools.values())

    def clear_server(self, server_id: str) -> None:
        """Unregister all tools associated with a server."""
        to_delete = [k for k, v in self._tools.items() if v.server_id == server_id]
        for k in to_delete:
            del self._tools[k]
        self._lookup = {k: v for k, v in self._lookup.items() if k[0] != server_id}
