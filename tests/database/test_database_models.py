"""
AgentShield AI — Database Models & Isolation Tests.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.database.base import Base
from agentshield.database.models import (
    ActivityEvent,
    Agent,
    ApprovalRequest,
    AuditLog,
    Integration,
    Policy,
    ThreatEvent,
    User,
)


@pytest.fixture
async def db_session():
    """Create an isolated in-memory SQLite database session for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


class TestDatabaseModels:
    async def test_user_creation_and_agent_relationship(self, db_session: AsyncSession):
        user = User(
            email="test@example.com",
            username="testuser",
            hashed_password="hashed_pwd_val",
        )
        db_session.add(user)
        await db_session.flush()

        assert user.id is not None
        assert user.created_at is not None

        agent = Agent(
            owner_user_id=user.id,
            agent_name="TestAgent",
            framework="LangGraph",
            credential_hash="hash_val",
        )
        db_session.add(agent)
        await db_session.flush()

        assert agent.id is not None
        assert agent.owner_user_id == user.id

    async def test_activity_event_model(self, db_session: AsyncSession):
        act = ActivityEvent(
            request_id="req-1",
            user_id="user-1",
            agent_id="agent-1",
            tool_name="bash_exec",
            operation="execute",
            decision="BLOCK",
            risk_level="HIGH",
        )
        db_session.add(act)
        await db_session.flush()
        assert act.decision == "BLOCK"
        assert act.created_at is not None

    async def test_threat_event_model(self, db_session: AsyncSession):
        threat = ThreatEvent(
            user_id="user-1",
            agent_id="agent-1",
            threat_type="PromptInjection",
            severity="HIGH",
            description="Detected prompt injection attempt",
        )
        db_session.add(threat)
        await db_session.flush()
        assert threat.severity == "HIGH"
        assert threat.status == "open"

    async def test_approval_request_model(self, db_session: AsyncSession):
        app = ApprovalRequest(
            user_id="user-1",
            agent_id="agent-1",
            request_id="req-2",
            tool_name="drop_table",
            operation="sql",
            risk_level="CRITICAL",
            description="Dropping user table",
        )
        db_session.add(app)
        await db_session.flush()
        assert app.status == "pending"

    async def test_policy_model(self, db_session: AsyncSession):
        pol = Policy(
            user_id="user-1",
            name="Block Dangerous Commands",
            category="command_exec",
            enforcement_mode="enforce",
        )
        db_session.add(pol)
        await db_session.flush()
        assert pol.is_enabled is True
        assert pol.version == 1

    async def test_audit_log_model(self, db_session: AsyncSession):
        audit = AuditLog(
            user_id="user-1",
            event_type="policy.created",
            resource_type="policy",
            resource_id="pol-1",
            description="Created policy",
        )
        db_session.add(audit)
        await db_session.flush()
        assert audit.created_at is not None

    async def test_integration_model(self, db_session: AsyncSession):
        integ = Integration(
            user_id="user-1",
            integration_name="Claude Agent SDK",
            integration_type="sdk",
            status="planned",
        )
        db_session.add(integ)
        await db_session.flush()
        assert integ.status == "planned"
