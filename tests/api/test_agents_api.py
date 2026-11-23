"""
AgentShield AI — Agents API Tests.
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


class TestAgentsAPI:
    async def test_create_agent_displays_credential_once(self, test_client: AsyncClient):
        token = await _register_and_login(test_client, "agentowner")
        headers = {"Authorization": f"Bearer {token}"}

        resp = await test_client.post(
            "/api/v1/agents",
            headers=headers,
            json={"agent_name": "TestBot", "framework": "OpenAI SDK", "description": "Helper"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["agent_name"] == "TestBot"
        assert "raw_credential" in data
        assert data["raw_credential"].startswith("ash_")
        assert "credential_hash" not in data

        # Subsequent list should NOT include raw_credential or credential_hash
        list_resp = await test_client.get("/api/v1/agents", headers=headers)
        assert list_resp.status_code == 200
        agents = list_resp.json()
        assert len(agents) == 1
        assert "raw_credential" not in agents[0]
        assert "credential_hash" not in agents[0]

    async def test_agent_authenticate_endpoint(self, test_client: AsyncClient):
        token = await _register_and_login(test_client, "authbotowner")
        headers = {"Authorization": f"Bearer {token}"}

        create_resp = await test_client.post(
            "/api/v1/agents",
            headers=headers,
            json={"agent_name": "AuthBot"},
        )
        raw_cred = create_resp.json()["raw_credential"]

        # Authenticate using the credential
        auth_resp = await test_client.post(
            "/api/v1/agents/authenticate",
            json={"credential": raw_cred},
        )
        assert auth_resp.status_code == 200
        data = auth_resp.json()
        assert data["authenticated"] is True
        assert data["agent"]["agent_name"] == "AuthBot"

    async def test_agent_authenticate_invalid_credential(self, test_client: AsyncClient):
        auth_resp = await test_client.post(
            "/api/v1/agents/authenticate",
            json={"credential": "ash_invalid_credential_token_123"},
        )
        assert auth_resp.status_code == 401

    async def test_rotate_agent_credential(self, test_client: AsyncClient):
        token = await _register_and_login(test_client, "rotateowner")
        headers = {"Authorization": f"Bearer {token}"}

        create_resp = await test_client.post(
            "/api/v1/agents",
            headers=headers,
            json={"agent_name": "RotatableBot"},
        )
        old_cred = create_resp.json()["raw_credential"]
        agent_id = create_resp.json()["id"]

        rotate_resp = await test_client.post(
            f"/api/v1/agents/{agent_id}/rotate-credential",
            headers=headers,
        )
        assert rotate_resp.status_code == 200
        new_cred = rotate_resp.json()["raw_credential"]
        assert new_cred != old_cred

        # Old credential should fail
        old_auth = await test_client.post(
            "/api/v1/agents/authenticate",
            json={"credential": old_cred},
        )
        assert old_auth.status_code == 401

        # New credential should succeed
        new_auth = await test_client.post(
            "/api/v1/agents/authenticate",
            json={"credential": new_cred},
        )
        assert new_auth.status_code == 200

    async def test_user_cannot_access_other_users_agent(self, test_client: AsyncClient):
        user1_token = await _register_and_login(test_client, "user1")
        user2_token = await _register_and_login(test_client, "user2")

        # user1 creates agent
        resp = await test_client.post(
            "/api/v1/agents",
            headers={"Authorization": f"Bearer {user1_token}"},
            json={"agent_name": "User1Bot"},
        )
        agent_id = resp.json()["id"]

        # user2 attempts to get user1's agent
        get_resp = await test_client.get(
            f"/api/v1/agents/{agent_id}",
            headers={"Authorization": f"Bearer {user2_token}"},
        )
        assert get_resp.status_code == 404
