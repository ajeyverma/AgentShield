"""
API tests for /api/v1/executions and /api/v1/tools (Phase 6).
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
async def test_execution_api_lifecycle(test_client: AsyncClient):
    headers = await _auth_headers(test_client, "gatekeeper")

    # 1. Register an Agent
    agent_resp = await test_client.post(
        "/api/v1/agents",
        json={"agent_name": "GateAgent", "framework": "custom", "description": "Gateway test agent"},
        headers=headers,
    )
    assert agent_resp.status_code == 201
    agent_id = agent_resp.json()["id"]

    # 2. Query /api/v1/tools
    tools_resp = await test_client.get("/api/v1/tools", headers=headers)
    assert tools_resp.status_code == 200
    tools = tools_resp.json()
    assert len(tools) >= 4
    tool_names = [t["tool_name"] for t in tools]
    assert "calculator" in tool_names

    # 3. Submit valid Execution Request (ALLOW outcome)
    exec_payload = {
        "agent_id": agent_id,
        "tool_name": "calculator",
        "action_name": "multiply",
        "arguments": {"a": 7, "b": 6},
    }
    resp = await test_client.post("/api/v1/executions", json=exec_payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert data["status"] == "COMPLETED"
    assert data["result"]["result"] == 42.0
    execution_id = data["execution_id"]

    # 4. Get Execution Details
    get_resp = await test_client.get(f"/api/v1/executions/{execution_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["execution_id"] == execution_id

    # 5. List Executions
    list_resp = await test_client.get("/api/v1/executions", headers=headers)
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_execution_api_approval_and_cancel_endpoints(test_client: AsyncClient):
    headers = await _auth_headers(test_client, "approver_user")

    agent_resp = await test_client.post(
        "/api/v1/agents",
        json={"agent_name": "ApprovalAgent", "framework": "custom"},
        headers=headers,
    )
    agent_id = agent_resp.json()["id"]

    # Create policy requiring approval
    await test_client.post(
        "/api/v1/policies",
        json={
            "name": "Require FS Approval",
            "category": "filesystem",
            "enforcement_mode": "enforce",
            "rules_json": '{"tools": ["sandbox_fs"], "outcome": "ASK_HUMAN"}',
            "is_enabled": True,
        },
        headers=headers,
    )

    # 1. Trigger ASK_HUMAN execution
    exec_resp = await test_client.post(
        "/api/v1/executions",
        json={
            "agent_id": agent_id,
            "tool_name": "sandbox_fs",
            "action_name": "create_file",
            "arguments": {"path": "api_test.txt", "content": "approval content"},
        },
        headers=headers,
    )
    assert exec_resp.status_code == 200
    data = exec_resp.json()
    assert data["decision"] == "ASK_HUMAN"
    assert data["status"] == "PENDING_APPROVAL"
    exec_id = data["execution_id"]

    # 2. Approve via API
    appr_resp = await test_client.post(
        f"/api/v1/executions/{exec_id}/approve",
        json={"approval_notes": "Looks safe to write"},
        headers=headers,
    )
    assert appr_resp.status_code == 200
    appr_data = appr_resp.json()
    assert appr_data["status"] == "COMPLETED"
    assert appr_data["result"]["status"] == "created"

    # 3. Trigger second execution and test cancel
    exec_resp2 = await test_client.post(
        "/api/v1/executions",
        json={
            "agent_id": agent_id,
            "tool_name": "sandbox_fs",
            "action_name": "create_file",
            "arguments": {"path": "to_cancel.txt", "content": "cancel me"},
        },
        headers=headers,
    )
    exec_id2 = exec_resp2.json()["execution_id"]

    cancel_resp = await test_client.post(
        f"/api/v1/executions/{exec_id2}/cancel",
        headers=headers,
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "CANCELLED"
