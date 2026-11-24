"""
Helper script to register the PoisonedWebpageDemoAgent with AgentShield.

Can register either:
1. Via HTTP API (when backend server is running on http://127.0.0.1:8000)
2. Directly via database session (when backend server is offline)
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import httpx
from agentshield.core.config import settings as core_settings
from agentshield.database.session import AsyncSessionLocal, initialize_database
from agentshield.database.models.user import User
from agentshield.identity.schemas import AgentCreate, UserCreate
from agentshield.identity.service import AgentService, UserService


AGENT_NAME = "PoisonedWebpageDemoAgent"
FRAMEWORK = "openai"
DESCRIPTION = "Demo agent that reads webpages and is protected by AgentShield against indirect prompt injection."
ENV_FILE = Path(__file__).resolve().parent / ".env"


async def register_direct_db() -> tuple[str, str]:
    """Register agent directly in the AgentShield database."""
    await initialize_database()
    async with AsyncSessionLocal() as session:
        user_svc = UserService(session)
        agent_svc = AgentService(session)

        # Ensure demo owner user exists
        demo_user = await user_svc.repo.get_by_username("demo_admin")
        if not demo_user:
            try:
                user_res = await user_svc.register(
                    UserCreate(
                        email="demo_admin@agentshield.local",
                        username="demo_admin",
                        password="DemoPassword123!",
                    )
                )
                user_id = user_res.id
            except Exception:
                u = await user_svc.repo.get_by_username("demo_admin")
                user_id = u.id if u else "usr-default-001"
        else:
            user_id = demo_user.id

        # Register agent
        created = await agent_svc.register_agent(
            owner_user_id=user_id,
            data=AgentCreate(
                agent_name=AGENT_NAME,
                framework=FRAMEWORK,
                description=DESCRIPTION,
            ),
        )
        return created.id, created.raw_credential


def register_http_api() -> tuple[str, str] | None:
    """Attempt registration via running HTTP backend."""
    try:
        url = "http://127.0.0.1:8000/api/v1/agents"
        resp = httpx.post(
            url,
            json={
                "agent_name": AGENT_NAME,
                "framework": FRAMEWORK,
                "description": DESCRIPTION,
            },
            timeout=3.0,
        )
        if resp.status_code == 201:
            data = resp.json()
            return data["id"], data["raw_credential"]
    except Exception:
        pass
    return None


def update_env_file(agent_id: str, raw_cred: str):
    """Save agent credentials into demo .env file."""
    lines = [
        f"# AgentShield Demo Agent Credentials",
        f"AGENTSHIELD_AGENT_ID={agent_id}",
        f"AGENTSHIELD_AGENT_CREDENTIAL={raw_cred}",
        f"AGENTSHIELD_AGENT_NAME={AGENT_NAME}",
        f"AGENTSHIELD_FRAMEWORK={FRAMEWORK}",
        f"AGENTSHIELD_BACKEND_URL=http://127.0.0.1:8000",
    ]
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


async def main():
    print("\n" + "=" * 65)
    print("  Registering PoisonedWebpageDemoAgent into AgentShield")
    print("=" * 65)

    # 1. Try HTTP API first
    res = register_http_api()
    source = "HTTP Backend API (http://127.0.0.1:8000)"

    # 2. If backend not running, register directly in database
    if not res:
        res = await register_direct_db()
        source = "Local AgentShield Database"

    agent_id, raw_cred = res
    update_env_file(agent_id, raw_cred)

    print(f"\n[OK] Agent Registered Successfully via {source}!")
    print(f"  • Name:        {AGENT_NAME}")
    print(f"  • Framework:   {FRAMEWORK}")
    print(f"  • Agent ID:    {agent_id}")
    print(f"  • Credential:  {raw_cred}")
    print(f"\n[OK] Saved credentials to: {ENV_FILE}")
    print("\nNext steps:")
    print("1. Open Desktop App -> Navigate to 'Agent Manager' to view this agent.")
    print("2. Run the demo: python demos/poisoned_webpage_agent/run_demo.py\n")


if __name__ == "__main__":
    asyncio.run(main())
