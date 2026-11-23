"""
Tests for MCP REST API Endpoints (Phase 8).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.database.base import Base
from agentshield.database.session import get_async_session
from apps.api.main import app


@pytest.fixture
async def test_client():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_async_session] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
    await engine.dispose()


async def _register_and_login(client: AsyncClient, username: str) -> str:
    await client.post(
        "/api/v1/auth/register",
        json={"email": f"{username}@test.com", "username": username, "password": "Password123!"},
    )
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": username, "password": "Password123!"},
    )
    return resp.json()["access_token"]


class TestMCPAPI:
    async def test_server_crud_lifecycle(self, test_client: AsyncClient):
        token = await _register_and_login(test_client, "mcpadmin")
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Register server
        create_payload = {
            "server_name": "sqlite-db",
            "server_description": "Local SQLite MCP Server",
            "transport_type": "stdio",
            "endpoint_or_command": "python",
            "args": ["-m", "mcp_server_sqlite"],
            "trust_classification": "internal",
        }
        res = await test_client.post("/api/v1/mcp/servers", headers=headers, json=create_payload)
        assert res.status_code == 201
        data = res.json()
        assert data["server_name"] == "sqlite-db"
        server_id = data["id"]

        # 2. List servers
        list_res = await test_client.get("/api/v1/mcp/servers", headers=headers)
        assert list_res.status_code == 200
        assert len(list_res.json()) == 1

        # 3. Get server details
        get_res = await test_client.get(f"/api/v1/mcp/servers/{server_id}", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["id"] == server_id

        # 4. Update server (disable it)
        patch_res = await test_client.patch(
            f"/api/v1/mcp/servers/{server_id}",
            headers=headers,
            json={"is_enabled": False, "server_description": "Updated description"},
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["is_enabled"] is False

        # 5. Delete server
        del_res = await test_client.delete(f"/api/v1/mcp/servers/{server_id}", headers=headers)
        assert del_res.status_code == 204

        # 6. Verify 404
        not_found_res = await test_client.get(f"/api/v1/mcp/servers/{server_id}", headers=headers)
        assert not_found_res.status_code == 404

    async def test_server_unwhitelisted_command_rejected(self, test_client: AsyncClient):
        token = await _register_and_login(test_client, "mcpuser2")
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "server_name": "malicious",
            "transport_type": "stdio",
            "endpoint_or_command": "powershell.exe",
        }
        res = await test_client.post("/api/v1/mcp/servers", headers=headers, json=payload)
        assert res.status_code == 403
        assert "whitelist" in res.json()["detail"].lower()

    async def test_server_ssrf_rejected(self, test_client: AsyncClient):
        token = await _register_and_login(test_client, "mcpuser3")
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "server_name": "aws-metadata",
            "transport_type": "streamable_http",
            "endpoint_or_command": "http://169.254.169.254/mcp",
        }
        res = await test_client.post("/api/v1/mcp/servers", headers=headers, json=payload)
        assert res.status_code == 403
        assert "ssrf" in res.json()["detail"].lower()

    async def test_gateway_message_endpoint(self, test_client: AsyncClient):
        token = await _register_and_login(test_client, "mcpuser4")
        headers = {"Authorization": f"Bearer {token}"}

        # Register server
        res = await test_client.post(
            "/api/v1/mcp/servers",
            headers=headers,
            json={"server_name": "test-fs", "transport_type": "stdio", "endpoint_or_command": "node"},
        )
        server_id = res.json()["id"]

        # Call gateway endpoint with initialize
        init_req = {"jsonrpc": "2.0", "id": "init-api-1", "method": "initialize"}
        gw_res = await test_client.post(
            f"/api/v1/mcp/gateway/{server_id}/message",
            headers=headers,
            json=init_req,
        )
        assert gw_res.status_code == 200
        data = gw_res.json()
        assert data["id"] == "init-api-1"
        assert "serverInfo" in data["result"]

        # Check activities endpoint
        act_res = await test_client.get("/api/v1/mcp/activities", headers=headers)
        assert act_res.status_code == 200
        assert isinstance(act_res.json(), list)
