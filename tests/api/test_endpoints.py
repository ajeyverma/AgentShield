"""
AgentShield AI — REST Endpoints Tests (Dashboard, Activity, Threats, Approvals, Policies, Audit, Integrations).
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


class TestRESTEndpoints:
    async def test_dashboard_summary_from_database(self, test_client: AsyncClient):
        headers = await _auth_headers(test_client, "dashuser")

        # Initial dashboard stats should be all 0
        resp = await test_client.get("/api/v1/dashboard/summary", headers=headers)
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_agents"] == 0
        assert stats["active_agents"] == 0

        # Create an agent
        await test_client.post("/api/v1/agents", headers=headers, json={"agent_name": "Bot1"})

        # Create an activity event
        await test_client.post(
            "/api/v1/activity",
            headers=headers,
            json={
                "request_id": "req-1",
                "agent_id": "bot-1",
                "tool_name": "web_search",
                "operation": "query",
                "decision": "BLOCK",
            },
        )

        # Check dashboard stats again
        resp2 = await test_client.get("/api/v1/dashboard/summary", headers=headers)
        stats2 = resp2.json()
        assert stats2["total_agents"] == 1
        assert stats2["active_agents"] == 1
        assert stats2["total_activities"] == 1
        assert stats2["blocked_actions"] == 1

    async def test_activity_pagination_and_filters(self, test_client: AsyncClient):
        headers = await _auth_headers(test_client, "actuser")

        for i in range(5):
            await test_client.post(
                "/api/v1/activity",
                headers=headers,
                json={
                    "request_id": f"req-{i}",
                    "agent_id": f"bot-{i%2}",
                    "tool_name": "tool",
                    "operation": "op",
                    "decision": "ALLOW" if i % 2 == 0 else "BLOCK",
                },
            )

        resp = await test_client.get("/api/v1/activity?page=1&size=2", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["total"] == 5

        # Filter by decision
        block_resp = await test_client.get("/api/v1/activity?decision=BLOCK", headers=headers)
        assert block_resp.json()["total"] == 2

    async def test_threats_crud(self, test_client: AsyncClient):
        headers = await _auth_headers(test_client, "threatuser")

        create_resp = await test_client.post(
            "/api/v1/threats",
            headers=headers,
            json={
                "agent_id": "bot-x",
                "threat_type": "Exfiltration",
                "severity": "CRITICAL",
                "description": "Sensitive data leak attempt",
            },
        )
        assert create_resp.status_code == 201
        threat_id = create_resp.json()["id"]

        # Update status
        patch_resp = await test_client.patch(
            f"/api/v1/threats/{threat_id}",
            headers=headers,
            json={"status": "resolved"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "resolved"

    async def test_approvals_patch_status_only(self, test_client: AsyncClient):
        headers = await _auth_headers(test_client, "appruser")

        create_resp = await test_client.post(
            "/api/v1/approvals",
            headers=headers,
            json={
                "agent_id": "bot-y",
                "request_id": "req-appr-1",
                "tool_name": "send_payment",
                "operation": "transfer",
                "description": "Transfer $1,000",
            },
        )
        assert create_resp.status_code == 201
        approval_id = create_resp.json()["id"]

        # Approve
        patch_resp = await test_client.patch(
            f"/api/v1/approvals/{approval_id}",
            headers=headers,
            json={"status": "approved"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "approved"

    async def test_policies_crud(self, test_client: AsyncClient):
        headers = await _auth_headers(test_client, "policyuser")

        # Create
        create_resp = await test_client.post(
            "/api/v1/policies",
            headers=headers,
            json={"name": "No Bash", "category": "exec", "enforcement_mode": "enforce"},
        )
        assert create_resp.status_code == 201
        pol_id = create_resp.json()["id"]

        # Update
        patch_resp = await test_client.patch(
            f"/api/v1/policies/{pol_id}",
            headers=headers,
            json={"enforcement_mode": "monitor"},
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["enforcement_mode"] == "monitor"

        # Delete
        del_resp = await test_client.delete(f"/api/v1/policies/{pol_id}", headers=headers)
        assert del_resp.status_code == 204

    async def test_integrations_crud(self, test_client: AsyncClient):
        headers = await _auth_headers(test_client, "integuser")

        create_resp = await test_client.post(
            "/api/v1/integrations",
            headers=headers,
            json={"integration_name": "OpenAI Agents", "integration_type": "sdk"},
        )
        assert create_resp.status_code == 201
        integ_id = create_resp.json()["id"]

        # List
        list_resp = await test_client.get("/api/v1/integrations", headers=headers)
        assert list_resp.status_code == 200
        assert len(list_resp.json()["items"]) == 1

        # Delete
        del_resp = await test_client.delete(f"/api/v1/integrations/{integ_id}", headers=headers)
        assert del_resp.status_code == 204
