"""
AgentShield AI — Auth API Integration Tests.
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
    """Create test client connected to an isolated in-memory database."""
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


class TestAuthAPI:
    async def test_register_user_success(self, test_client: AsyncClient):
        payload = {
            "email": "alice@example.com",
            "username": "alice",
            "password": "SuperSecretPassword123!",
        }
        resp = await test_client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "alice@example.com"
        assert data["username"] == "alice"
        assert "hashed_password" not in data
        assert "id" in data

    async def test_register_duplicate_email_fails(self, test_client: AsyncClient):
        payload = {
            "email": "dup@example.com",
            "username": "user1",
            "password": "Password123!",
        }
        resp = await test_client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 201

        # Second registration with same email
        payload2 = {
            "email": "dup@example.com",
            "username": "user2",
            "password": "Password123!",
        }
        resp2 = await test_client.post("/api/v1/auth/register", json=payload2)
        assert resp2.status_code == 400
        assert "already exists" in resp2.json()["detail"]

    async def test_login_success(self, test_client: AsyncClient):
        # Register first
        await test_client.post(
            "/api/v1/auth/register",
            json={"email": "login@example.com", "username": "loginuser", "password": "Password123!"},
        )

        # Login with email
        resp = await test_client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "login@example.com", "password": "Password123!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == "loginuser"

        # Login with username
        resp2 = await test_client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "loginuser", "password": "Password123!"},
        )
        assert resp2.status_code == 200

    async def test_login_incorrect_password(self, test_client: AsyncClient):
        await test_client.post(
            "/api/v1/auth/register",
            json={"email": "badpwd@example.com", "username": "badpwd", "password": "Password123!"},
        )

        resp = await test_client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "badpwd", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401
        assert "Invalid username/email or password" in resp.json()["detail"]

    async def test_get_current_user_me(self, test_client: AsyncClient):
        # Register & login
        await test_client.post(
            "/api/v1/auth/register",
            json={"email": "me@example.com", "username": "meuser", "password": "Password123!"},
        )
        login_resp = await test_client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "meuser", "password": "Password123!"},
        )
        token = login_resp.json()["access_token"]

        # Call /auth/me with token
        resp = await test_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "meuser"

    async def test_unauthenticated_request_fails(self, test_client: AsyncClient):
        resp = await test_client.get("/api/v1/auth/me")
        assert resp.status_code == 401
