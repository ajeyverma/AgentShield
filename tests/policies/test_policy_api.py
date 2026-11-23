"""
AgentShield AI — Policy & Emergency REST API Tests (Phase 10).

Verifies /api/v1/policies and /api/v1/security/emergency-controls endpoints.
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
async def test_policy_api_complete_flow(test_client: AsyncClient):
    headers = await _auth_headers(test_client, "policy_manager")

    # 1. Create Policy
    create_resp = await test_client.post(
        "/api/v1/policies",
        json={
            "name": "Network Restriction",
            "category": "network",
            "priority": 15,
            "decision": "BLOCK",
            "tool_scope": "http_client",
        },
        headers=headers,
    )
    assert create_resp.status_code == 201
    pol_id = create_resp.json()["id"]
    assert create_resp.json()["priority"] == 15

    # 2. Simulate policy
    sim_resp = await test_client.post(
        "/api/v1/policies/simulate",
        json={
            "tool_name": "http_client",
            "operation": "fetch",
            "arguments": {"url": "https://evil.com"},
        },
        headers=headers,
    )
    assert sim_resp.status_code == 200
    assert sim_resp.json()["simulated_decision"] == "BLOCK"
    assert sim_resp.json()["executed_real_tool"] is False

    # 3. Disable policy
    dis_resp = await test_client.post(f"/api/v1/policies/{pol_id}/disable", headers=headers)
    assert dis_resp.status_code == 200
    assert dis_resp.json()["is_enabled"] is False

    # 4. Duplicate policy
    dup_resp = await test_client.post(f"/api/v1/policies/{pol_id}/duplicate", headers=headers)
    assert dup_resp.status_code == 201
    assert dup_resp.json()["name"].startswith("Copy of")

    # 5. Version history
    hist_resp = await test_client.get(f"/api/v1/policies/{pol_id}/history", headers=headers)
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()) >= 1


@pytest.mark.asyncio
async def test_emergency_controls_api_flow(test_client: AsyncClient):
    headers = await _auth_headers(test_client, "emergency_admin")

    # 1. Check status (initially not in lockdown)
    status_resp = await test_client.get("/api/v1/security/emergency-status", headers=headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["is_lockdown_active"] is False

    # 2. Activate emergency lockdown
    act_resp = await test_client.post(
        "/api/v1/security/emergency-controls",
        json={
            "control_type": "PAUSE_EXECUTIONS",
            "target_identifier": "*",
            "reason": "Active intrusion detected",
        },
        headers=headers,
    )
    assert act_resp.status_code == 201
    control_id = act_resp.json()["id"]

    # 3. Verify status shows lockdown
    status_resp2 = await test_client.get("/api/v1/security/emergency-status", headers=headers)
    assert status_resp2.status_code == 200
    assert status_resp2.json()["is_lockdown_active"] is True
    assert status_resp2.json()["active_controls_count"] == 1

    # 4. Revoke control
    rev_resp = await test_client.post(
        f"/api/v1/security/emergency-controls/{control_id}/revoke",
        json={"reason": "Intrusion contained"},
        headers=headers,
    )
    assert rev_resp.status_code == 200
    assert rev_resp.json()["is_active"] is False
