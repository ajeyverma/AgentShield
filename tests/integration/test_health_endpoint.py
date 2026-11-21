"""
Integration tests for the AgentShield backend health check endpoint.

Uses httpx.AsyncClient against the FastAPI test application (no live server
required).  Tests confirm:
  - GET /api/v1/health returns 200.
  - Response contains expected fields.
  - Version matches the configured app version.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.main import app


@pytest.fixture
async def client():
    """Provide an async test client for the FastAPI app."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c


class TestHealthEndpoint:
    async def test_health_returns_200(self, client: AsyncClient):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200

    async def test_health_response_shape(self, client: AsyncClient):
        response = await client.get("/api/v1/health")
        data = response.json()
        assert data["status"] == "healthy"
        assert "service" in data
        assert "version" in data
        assert "environment" in data
        assert "api_prefix" in data
        assert "timestamp" in data
        assert "python_version" in data

    async def test_health_version_matches_config(self, client: AsyncClient):
        from agentshield.core.config import settings

        response = await client.get("/api/v1/health")
        data = response.json()
        assert data["version"] == settings.app_version

    async def test_health_api_prefix_correct(self, client: AsyncClient):
        response = await client.get("/api/v1/health")
        data = response.json()
        assert data["api_prefix"] == "/api/v1"

    async def test_docs_endpoint_accessible(self, client: AsyncClient):
        response = await client.get("/api/v1/docs")
        assert response.status_code == 200
