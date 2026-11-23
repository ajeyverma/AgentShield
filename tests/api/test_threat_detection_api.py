"""
API tests for /api/v1/threat-detection endpoints (Phase 5).
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
async def test_threat_detection_endpoints(test_client: AsyncClient):
    headers = await _auth_headers(test_client, "threat_officer")

    # 1. Register agent
    resp = await test_client.post(
        "/api/v1/agents",
        json={"agent_name": "GuardBot", "framework": "custom", "description": "Security test agent"},
        headers=headers,
    )
    assert resp.status_code == 201
    agent_id = resp.json()["id"]

    # 2. List Detectors
    resp = await test_client.get("/api/v1/threat-detection/detectors", headers=headers)
    assert resp.status_code == 200
    detectors = resp.json()
    assert len(detectors) >= 6
    assert any(d["detector_id"] == "DET-PI-001" for d in detectors)

    # 3. Analyze Action Request
    analyze_payload = {
        "action_request": {
            "tenant_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "tool_name": "terminal",
            "tool_category": "TERMINAL",
            "operation": "execute",
            "arguments": {"command": "rm -rf /"},
            "resource": "rm -rf /",
            "integration_type": "API",
        },
        "provenance": None,
        "relevant_history": [],
    }
    resp = await test_client.post("/api/v1/threat-detection/analyze", json=analyze_payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["findings"]) >= 1
    assert data["findings"][0]["severity"] == "CRITICAL"

    # 4. Summary
    resp = await test_client.get("/api/v1/threat-detection/summary", headers=headers)
    assert resp.status_code == 200
    summary = resp.json()
    assert "total_findings" in summary
    assert "category_distribution" in summary

    # 5. Findings list
    resp = await test_client.get("/api/v1/threat-detection/findings", headers=headers)
    assert resp.status_code == 200
    findings_data = resp.json()
    assert "items" in findings_data
