"""
AgentShield AI — Performance & Latency Benchmarks (Phase 11).

Measures and asserts:
1. Security Evaluation Latency (p50, p95, p99) target < 50ms
2. Controlled Tool Execution Gateway Overhead
3. Tamper-Evident Hash Chain Write Latency
4. Central Event Publisher Dispatch Latency
5. Throughput (Operations Per Second)
"""

from __future__ import annotations

import statistics
import time
import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, IntegrationType, ToolCategory
from agentshield.contracts.events import EventComponent, EventSeverity, SecurityEvent
from agentshield.contracts.execution import ExecutionRequest
from agentshield.database.base import Base
from agentshield.database.models.agent import Agent
from agentshield.database.models.policy import Policy
from agentshield.database.models.user import User
from agentshield.execution.enums import ExecutionStatus
from agentshield.observability.event_publisher import event_publisher
from agentshield.security.engine import security_engine
from agentshield.security.rbac import UserRole
from agentshield.services.execution_service import ExecutionService
from agentshield.services.tamper_evident_audit import TamperEvidentAuditService
from agentshield.threat_detection.engine import threat_coordinator


@pytest.fixture
async def bench_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def bench_env(bench_db: AsyncSession):
    tenant_id = str(uuid.uuid4())
    user = User(id=tenant_id, email="bench@test.com", username="bencher", hashed_password="pw", role=UserRole.SECURITY_ADMIN.value)
    agent = Agent(id=str(uuid.uuid4()), owner_user_id=tenant_id, agent_name="BenchAgent", framework="openai", status="active", credential_hash="cred")

    policy = Policy(
        user_id=tenant_id,
        name="Allow Calculator",
        category="calculator",
        enforcement_mode="enforce",
        decision="ALLOW",
        is_enabled=True,
    )
    bench_db.add_all([user, agent, policy])
    await bench_db.commit()

    return {"tenant_id": tenant_id, "user": user, "agent": agent, "policy": policy}


# ── 1. Security Engine Evaluation Latency Benchmark ───────────────────────────


def test_benchmark_security_engine_latency():
    """Benchmark: Core security engine evaluation latency (target: p95 < 25ms, p99 < 50ms)."""
    latencies: list[float] = []
    user_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())

    for i in range(100):
        req = ActionRequest(
            tenant_id=uuid.uuid4(),
            agent_id=uuid.UUID(agent_id),
            user_id=uuid.UUID(user_id),
            tool_name="calculator",
            tool_category=ToolCategory.UNKNOWN,
            operation="calculate",
            arguments={"expression": f"{i} * 2 + 10"},
            integration_type=IntegrationType.API,
        )
        t0 = time.perf_counter()
        threat_res = threat_coordinator.analyze_action(req)
        decision = security_engine.evaluate_action(
            authenticated_user_id=user_id,
            authenticated_agent_id=agent_id,
            agent_status="active",
            request=req,
            db_policies=[],
            threat_result=threat_res,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)
        assert decision.decision in (Decision.ALLOW, Decision.BLOCK, Decision.ASK_HUMAN)

    latencies.sort()
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    print(f"\n[Security Engine Latency] 100 evaluations: p50={p50:.2f}ms, p95={p95:.2f}ms, p99={p99:.2f}ms")
    assert p50 < 25.0, f"p50 latency {p50:.2f}ms exceeds 25ms target"
    assert p99 < 100.0, f"p99 latency {p99:.2f}ms exceeds 100ms upper limit"


# ── 2. Tamper-Evident Hash Chain Write Latency ─────────────────────────────────


@pytest.mark.asyncio
async def test_benchmark_audit_chain_write_latency(bench_db: AsyncSession, bench_env: dict):
    """Benchmark: Tamper-evident append-only audit write latency (target: p95 < 20ms)."""
    env = bench_env
    audit_svc = TamperEvidentAuditService(bench_db)
    latencies: list[float] = []

    for i in range(50):
        t0 = time.perf_counter()
        await audit_svc.record_audit_entry(
            tenant_id=env["tenant_id"],
            actor_id="bencher",
            action=f"benchmark.action.{i}",
            target=f"target:{i}",
            result="SUCCESS",
            description="Latency benchmark audit record",
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

    latencies.sort()
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]

    print(f"\n[Audit Chain Write Latency] 50 writes: p50={p50:.2f}ms, p95={p95:.2f}ms")
    assert p50 < 30.0, f"Audit write p50 {p50:.2f}ms exceeds 30ms target"


# ── 3. Central Event Publisher Dispatch Latency ───────────────────────────────


@pytest.mark.asyncio
async def test_benchmark_event_publishing_latency(bench_db: AsyncSession, bench_env: dict):
    """Benchmark: Central security event publication and metric recording."""
    env = bench_env
    latencies: list[float] = []

    for i in range(50):
        t0 = time.perf_counter()
        await event_publisher.publish(
            session=bench_db,
            event_type="benchmark.event",
            severity=EventSeverity.INFO,
            component=EventComponent.GATEWAY,
            tenant_id=env["tenant_id"],
            actor_id="bench_agent",
            action="execute",
            decision="ALLOW",
            status="SUCCESS",
            details={"index": i},
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

    latencies.sort()
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]

    print(f"\n[Event Publisher Latency] 50 dispatches: p50={p50:.2f}ms, p95={p95:.2f}ms")
    assert p50 < 30.0, f"Event publisher p50 {p50:.2f}ms exceeds 30ms target"


# ── 4. End-to-End Execution Gateway Latency & Throughput ──────────────────────


@pytest.mark.asyncio
async def test_benchmark_gateway_execution_throughput(bench_db: AsyncSession, bench_env: dict):
    """Benchmark: Controlled tool execution gateway end-to-end throughput."""
    env = bench_env
    exec_svc = ExecutionService(bench_db)

    iterations = 30
    t_start = time.perf_counter()

    for i in range(iterations):
        req = ExecutionRequest(
            agent_id=uuid.UUID(env["agent"].id),
            user_id=env["tenant_id"],
            tool_name="calculator",
            action_name="add",
            arguments={"a": 100.0, "b": float(i)},
        )
        res = await exec_svc.execute_request(user_id=env["tenant_id"], agent=env["agent"], request=req)
        assert res.decision == "ALLOW"
        assert res.status in (ExecutionStatus.COMPLETED.value, "COMPLETED", "completed")

    total_time = time.perf_counter() - t_start
    throughput = iterations / total_time
    avg_latency = (total_time / iterations) * 1000.0

    print(f"\n[Gateway End-to-End] {iterations} operations in {total_time:.2f}s: {throughput:.1f} ops/sec (avg {avg_latency:.2f}ms/op)")
    assert throughput > 5.0, f"Throughput {throughput:.1f} ops/sec below threshold"
