"""
AgentShield AI — MCP Server Registry Service (Phase 8).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.database.models.mcp import MCPServerModel
from agentshield.mcp_gateway.configuration import MCPGatewayConfig, default_mcp_gateway_config
from agentshield.mcp_gateway.exceptions import (
    MCPSSRFError,
    MCPUntrustedCommandError,
    NotFoundError,
    ValidationError,
)


class MCPServerRegistry:
    """
    Service managing registered MCP servers with tenant isolation,
    executable command whitelisting, and SSRF validation.
    """

    def __init__(self, config: MCPGatewayConfig | None = None) -> None:
        self.config = config or default_mcp_gateway_config

    def validate_server_config(
        self,
        transport_type: str,
        endpoint_or_command: str,
    ) -> None:
        """Validate server launch parameters against gateway security controls."""
        transport_type = transport_type.lower()
        if transport_type not in ("stdio", "streamable_http", "sse", "http"):
            raise ValidationError(
                message=f"Unsupported MCP transport: '{transport_type}'. Supported: 'stdio', 'streamable_http', 'sse'.",
                field="transport_type",
            )

        if transport_type == "stdio":
            if not self.config.is_executable_allowed(endpoint_or_command):
                raise MCPUntrustedCommandError(endpoint_or_command)
        else:
            is_valid, reason = self.config.validate_endpoint_url(endpoint_or_command)
            if not is_valid:
                raise MCPSSRFError(reason=reason, endpoint=endpoint_or_command)

    async def register_server(
        self,
        db: AsyncSession,
        user_id: str,
        server_name: str,
        transport_type: str,
        endpoint_or_command: str,
        server_description: str | None = None,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        trust_classification: str = "untrusted",
    ) -> MCPServerModel:
        """Register a new MCP server for a tenant."""
        self.validate_server_config(transport_type, endpoint_or_command)

        # Check for unique name per tenant
        query = select(MCPServerModel).where(
            MCPServerModel.user_id == user_id,
            MCPServerModel.server_name == server_name,
        )
        res = await db.execute(query)
        if res.scalar_one_or_none():
            raise ValidationError(
                message=f"An MCP server named '{server_name}' is already registered for this user.",
                field="server_name",
            )

        server = MCPServerModel(
            id=str(uuid4()),
            user_id=user_id,
            server_name=server_name,
            server_description=server_description,
            transport_type=transport_type.lower(),
            endpoint_or_command=endpoint_or_command,
            args_json=json.dumps(args or []),
            env_json=json.dumps(env or {}),
            protocol_version="2024-11-05",
            connection_status="disconnected",
            is_enabled=True,
            trust_classification=trust_classification,
        )
        db.add(server)
        await db.commit()
        await db.refresh(server)
        return server

    async def get_server(
        self,
        db: AsyncSession,
        server_id: str,
        user_id: str,
    ) -> MCPServerModel:
        """Get an MCP server ensuring tenant isolation."""
        query = select(MCPServerModel).where(
            MCPServerModel.id == server_id,
            MCPServerModel.user_id == user_id,
        )
        res = await db.execute(query)
        server = res.scalar_one_or_none()
        if not server:
            raise NotFoundError(resource_type="MCPServer", resource_id=server_id)
        return server

    async def list_servers(
        self,
        db: AsyncSession,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[MCPServerModel]:
        """List all MCP servers owned by the tenant."""
        query = (
            select(MCPServerModel)
            .where(MCPServerModel.user_id == user_id)
            .order_by(MCPServerModel.server_name.asc())
            .offset(offset)
            .limit(limit)
        )
        res = await db.execute(query)
        return list(res.scalars().all())

    async def update_server_status(
        self,
        db: AsyncSession,
        server_id: str,
        user_id: str,
        status: str,
        error_message: str | None = None,
        capabilities: dict[str, Any] | None = None,
    ) -> MCPServerModel:
        """Update connection status and last connected timestamp."""
        server = await self.get_server(db, server_id, user_id)
        server.connection_status = status
        if error_message is not None:
            server.error_message = error_message
        if capabilities is not None:
            server.capabilities_json = json.dumps(capabilities)
        if status == "connected":
            server.last_connected_at = datetime.now(timezone.utc)
            server.error_message = None

        await db.commit()
        await db.refresh(server)
        return server

    async def delete_server(
        self,
        db: AsyncSession,
        server_id: str,
        user_id: str,
    ) -> bool:
        """Delete an MCP server registration."""
        server = await self.get_server(db, server_id, user_id)
        await db.delete(server)
        await db.commit()
        return True
