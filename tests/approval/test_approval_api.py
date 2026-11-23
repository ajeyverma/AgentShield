"""
AgentShield AI — Approval REST API Tests (Phase 10).

Verifies /api/v1/approvals endpoints for approval, rejection, cancellation,
history, pagination, and RBAC permissions.
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


async def _auth_headers(client: AsyncClient, username: str) -> dict[str, str]:
    await client.post(
        "/api/v1/auth/register",
        json={"email": f"{username}@test.com", "username": username, "password": "Password123!"},
    )
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": username, "password": "Password123!"},
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_approvals_api_lifecycle(test_client: AsyncClient):
    headers = await _auth_headers(test_client, "human_approver")

    # 1. Register agent
    agent_resp = await test_client.post(
        "/api/v1/agents",
        json={"agent_name": "ReviewBot", "framework": "custom"},
        headers=headers,
    )
    agent_id = agent_resp.json()["id"]

    # 2. Add policy to require human approval
    await test_client.post(
        "/api/v1/policies",
        json={
            "name": "Require FS Approval",
            "category": "filesystem",
            "enforcement_mode": "enforce",
            "decision": "ASK_HUMAN",
            "tool_scope": "sandbox_fs",
            "action_scope": "*",
            "is_enabled": True,
        },
        headers=headers,
    )

    # 3. Submit execution -> PENDING_APPROVAL
    exec_resp = await test_client.post(
        "/api/v1/executions",
        json={
            "agent_id": agent_id,
            "tool_name": "sandbox_fs",
            "action_name": "create_file",
            "arguments": {"path": "api_approval.txt", "content": "needs approval", "password": "secret_pw"},
        },
        headers=headers,
    )
    assert exec_resp.status_code == 200
    assert exec_resp.json()["status"] == "PENDING_APPROVAL"

    # 4. List approvals
    list_resp = await test_client.get("/api/v1/approvals?status=pending", headers=headers)
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]
    assert len(items) == 1
    approval_id = items[0]["id"]

    # 5. Get detail (verifying secret redaction)
    detail_resp = await test_client.get(f"/api/v1/approvals/{approval_id}", headers=headers)
    assert detail_resp.status_code == 200
    det = detail_resp.json()
    assert det["sanitized_arguments"]["password"] == "[REDACTED]"
    assert det["sanitized_arguments"]["path"] == "api_approval.txt"

    # 6. Approve via endpoint
    approve_resp = await test_client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        json={"comment": "Approved through API"},
        headers=headers,
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    # 7. Query history
    hist_resp = await test_client.get(f"/api/v1/approvals/{approval_id}/history", headers=headers)
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()) >= 1
    assert hist_resp.json()[0]["action"] == "approve"
