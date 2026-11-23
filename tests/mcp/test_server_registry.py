"""
Tests for MCP Server Registry, Whitelisting, and SSRF Prevention (Phase 8).
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentshield.mcp_gateway.configuration import MCPGatewayConfig
from agentshield.mcp_gateway.exceptions import (
    MCPSSRFError,
    MCPUntrustedCommandError,
    NotFoundError,
    ValidationError,
)
from agentshield.mcp_gateway.registry.server_registry import MCPServerRegistry


def test_config_executable_whitelist():
    config = MCPGatewayConfig()
    assert config.is_executable_allowed("python") is True
    assert config.is_executable_allowed("python3") is True
    assert config.is_executable_allowed("node") is True
    assert config.is_executable_allowed("npx") is True
    assert config.is_executable_allowed("docker") is True
    assert config.is_executable_allowed("powershell.exe") is False
    assert config.is_executable_allowed("cmd.exe") is False
    assert config.is_executable_allowed("sh") is False
    assert config.is_executable_allowed("bash") is False
    assert config.is_executable_allowed("nc") is False
    assert config.is_executable_allowed("malicious_binary") is False


def test_ssrf_validation_blocks_private_ips():
    config = MCPGatewayConfig()

    # Loopback
    is_valid, reason = config.validate_endpoint_url("http://127.0.0.1:8080/mcp")
    assert is_valid is False
    assert "SSRF" in reason or "blocked" in reason

    # Localhost
    is_valid, reason = config.validate_endpoint_url("http://localhost:8000/rpc")
    assert is_valid is False

    # Link-local / Cloud metadata
    is_valid, reason = config.validate_endpoint_url("http://169.254.169.254/latest/meta-data")
    assert is_valid is False

    # RFC 1918 Private networks
    is_valid, reason = config.validate_endpoint_url("http://10.0.1.5:9000/mcp")
    assert is_valid is False
    is_valid, reason = config.validate_endpoint_url("http://192.168.1.100:3000/mcp")
    assert is_valid is False
    is_valid, reason = config.validate_endpoint_url("http://172.16.0.1/mcp")
    assert is_valid is False

    # Invalid scheme
    is_valid, reason = config.validate_endpoint_url("file:///etc/passwd")
    assert is_valid is False


@pytest.mark.asyncio
async def test_server_registration_and_tenant_isolation(db_session: AsyncSession):
    registry = MCPServerRegistry()
    user_a = "user-tenant-a-1111"
    user_b = "user-tenant-b-2222"

    # Register valid stdio server for User A
    server_a = await registry.register_server(
        db=db_session,
        user_id=user_a,
        server_name="sqlite-service",
        transport_type="stdio",
        endpoint_or_command="python",
        server_description="Tenant A SQLite MCP Server",
        args=["-m", "mcp_server_sqlite"],
    )
    assert server_a.id is not None
    assert server_a.server_name == "sqlite-service"
    assert server_a.user_id == user_a

    # User A can retrieve it
    retrieved = await registry.get_server(db_session, server_a.id, user_a)
    assert retrieved.id == server_a.id

    # User B CANNOT retrieve User A's server (Tenant Isolation)
    with pytest.raises(NotFoundError):
        await registry.get_server(db_session, server_a.id, user_b)

    # User B list shows 0 servers
    b_servers = await registry.list_servers(db_session, user_b)
    assert len(b_servers) == 0

    # User A list shows 1 server
    a_servers = await registry.list_servers(db_session, user_a)
    assert len(a_servers) == 1


@pytest.mark.asyncio
async def test_server_registration_rejects_unwhitelisted_command(db_session: AsyncSession):
    registry = MCPServerRegistry()
    with pytest.raises(MCPUntrustedCommandError):
        await registry.register_server(
            db=db_session,
            user_id="user-123",
            server_name="malicious-server",
            transport_type="stdio",
            endpoint_or_command="powershell.exe",
        )


@pytest.mark.asyncio
async def test_server_registration_rejects_ssrf_endpoint(db_session: AsyncSession):
    registry = MCPServerRegistry()
    with pytest.raises(MCPSSRFError):
        await registry.register_server(
            db=db_session,
            user_id="user-123",
            server_name="ssrf-server",
            transport_type="streamable_http",
            endpoint_or_command="http://169.254.169.254/mcp",
        )


@pytest.mark.asyncio
async def test_server_status_update_and_deletion(db_session: AsyncSession):
    registry = MCPServerRegistry()
    user_id = "user-lifecycle-test"

    server = await registry.register_server(
        db=db_session,
        user_id=user_id,
        server_name="node-fs",
        transport_type="stdio",
        endpoint_or_command="node",
    )
    assert server.connection_status == "disconnected"

    # Update to connected
    updated = await registry.update_server_status(
        db_session, server.id, user_id, status="connected", capabilities={"tools": {}}
    )
    assert updated.connection_status == "connected"
    assert updated.last_connected_at is not None

    # Delete
    del_ok = await registry.delete_server(db_session, server.id, user_id)
    assert del_ok is True

    with pytest.raises(NotFoundError):
        await registry.get_server(db_session, server.id, user_id)
