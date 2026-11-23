"""
AgentShield AI — Security Service & API Integration Tests (Phase 4).
"""

from __future__ import annotations

import uuid
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


async def _setup_user_and_agent(client: AsyncClient, prefix: str):
    # Register & Login
    await client.post(
        "/api/v1/auth/register",
        json={"email": f"{prefix}@test.com", "username": prefix, "password": "Password123!"},
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": prefix, "password": "Password123!"},
    )
    token = login_resp.json()["access_token"]
    user_id = login_resp.json()["user"]["id"]

    # Register Agent
    headers = {"Authorization": f"Bearer {token}"}
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=headers,
        json={"agent_name": f"{prefix}Bot", "framework": "OpenAI"},
    )
    agent_data = agent_resp.json()
    return token, user_id, agent_data["id"], agent_data["raw_credential"]


class TestSecurityServiceAndAPI:
    async def test_security_evaluate_allow_flow(self, test_client: AsyncClient):
        token, user_id, agent_id, raw_cred = await _setup_user_and_agent(test_client, "evalallow")

        payload = {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "user_id": user_id,
            "integration_type": "SDK_OPENAI",
            "tool_name": "read_docs",
            "tool_category": "FILE_SYSTEM",
            "operation": "read",
            "resource": "/workspace/readme.md",
        }

        # Evaluate via X-Agent-Credential
        resp = await test_client.post(
            "/api/v1/security/evaluate",
            headers={"X-Agent-Credential": raw_cred},
            json=payload,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "ALLOW"
        assert data["approval_required"] is False
        assert "evaluation_duration_ms" in data

    async def test_security_evaluate_block_flow(self, test_client: AsyncClient):
        token, user_id, agent_id, raw_cred = await _setup_user_and_agent(test_client, "evalblock")

        payload = {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "user_id": user_id,
            "integration_type": "SDK_OPENAI",
            "tool_name": "read_file",
            "tool_category": "FILE_SYSTEM",
            "operation": "read",
            "resource": "/etc/shadow",  # Prohibited path
        }

        resp = await test_client.post(
            "/api/v1/security/evaluate",
            headers={"X-Agent-Credential": raw_cred},
            json=payload,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "BLOCK"
        assert data["risk_level"] == "CRITICAL"
        assert any("protected system path" in r for r in data["reasons"])

    async def test_security_evaluate_ask_human_flow(self, test_client: AsyncClient):
        token, user_id, agent_id, raw_cred = await _setup_user_and_agent(test_client, "evalask")

        payload = {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "user_id": user_id,
            "integration_type": "SDK_OPENAI",
            "tool_name": "file_delete",
            "tool_category": "FILE_SYSTEM",
            "operation": "delete",
            "resource": "/home/user/project/file.bin",
        }

        resp = await test_client.post(
            "/api/v1/security/evaluate",
            headers={"X-Agent-Credential": raw_cred},
            json=payload,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "ASK_HUMAN"
        assert data["approval_required"] is True
        assert data["approval_id"] is not None

        # Verify an ApprovalRequest record was persisted in database
        appr_resp = await test_client.get(
            f"/api/v1/approvals/{data['approval_id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert appr_resp.status_code == 200
        assert appr_resp.json()["status"] == "pending"

    async def test_security_decisions_history_and_isolation(self, test_client: AsyncClient):
        token1, u1, a1, cred1 = await _setup_user_and_agent(test_client, "userone")
        token2, u2, a2, cred2 = await _setup_user_and_agent(test_client, "usertwo")

        # Evaluate action for userone
        await test_client.post(
            "/api/v1/security/evaluate",
            headers={"X-Agent-Credential": cred1},
            json={
                "tenant_id": str(uuid.uuid4()),
                "agent_id": a1,
                "user_id": u1,
                "integration_type": "SDK_CUSTOM",
                "tool_name": "search_db",
                "operation": "read",
            },
        )

        # Userone checks history
        h1 = await test_client.get(
            "/api/v1/security/decisions",
            headers={"Authorization": f"Bearer {token1}"},
        )
        assert h1.status_code == 200
        assert h1.json()["total"] == 1

        # Usertwo checks history — must be empty (isolated)
        h2 = await test_client.get(
            "/api/v1/security/decisions",
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert h2.status_code == 200
        assert h2.json()["total"] == 0
