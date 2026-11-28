"""
Configuration settings for AgentShield Poisoned Webpage Demo Agent.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from pydantic import BaseModel, Field

if getattr(sys, "frozen", False):
    EXE_DIR = Path(sys.executable).parent
    DEMO_ROOT = EXE_DIR if (EXE_DIR / "data").exists() else (EXE_DIR / "demos" / "agent")
    REPO_ROOT = EXE_DIR
else:
    DEMO_ROOT = Path(__file__).resolve().parent
    REPO_ROOT = DEMO_ROOT.parents[1]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(DEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_ROOT))

# Load .env file with demo agent credentials
if getattr(sys, "frozen", False):
    for candidate in [REPO_ROOT / ".env", DEMO_ROOT / ".env"]:
        if candidate.exists():
            load_dotenv(candidate, override=True)
else:
    load_dotenv(DEMO_ROOT / ".env", override=True)

DATA_DIR = DEMO_ROOT / "data"
RESULTS_DIR = DEMO_ROOT / "results"
DATA_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


class DemoSettings(BaseModel):
    # Agent & Tenant Identity
    agent_id: str = Field(default="demo-webpage-agent-001")
    agent_name: str = Field(default="Subway Coders")
    tenant_id: str = Field(default="demo-tenant-001")
    agent_credential: str = Field(default="agsh_demo_secret_credential_token")

    # Backend Connection
    backend_url: str = Field(default="http://localhost:8000")
    api_prefix: str = Field(default="/api/v1")
    use_in_process_engine: bool = Field(default=True, description="Use in-process AgentShield engine if backend HTTP is offline")

    # Model Configuration
    openai_api_key: str | None = Field(default=None)
    model_name: str = Field(default="gpt-4o-mini")
    gemini_api_key: str | None = Field(default=None)
    gemini_model: str = Field(default="gemini-3.1-flash-lite")
    openrouter_api_key: str | None = Field(default=None)
    openrouter_model: str = Field(default="meta-llama/llama-3.3-70b-instruct")
    huggingface_api_key: str | None = Field(default=None)
    huggingface_model: str = Field(default="meta-llama/Llama-3.1-8B-Instruct")

    # Paths
    demo_root: Path = Field(default=DEMO_ROOT)
    data_dir: Path = Field(default=DATA_DIR)
    results_dir: Path = Field(default=RESULTS_DIR)
    dummy_secret_file: Path = Field(default=DATA_DIR / "dummy_secret.txt")
    email_log_file: Path = Field(default=DATA_DIR / "mock_email_log.json")

    @classmethod
    def load(cls) -> DemoSettings:
        # Load from repo root .env as well as demo root .env
        load_dotenv(REPO_ROOT / ".env", override=False)
        load_dotenv(DEMO_ROOT / ".env", override=True)
        return cls(
            agent_id=os.environ.get("AGENTSHIELD_AGENT_ID", "demo-webpage-agent-001"),
            tenant_id=os.environ.get("AGENTSHIELD_TENANT_ID", "demo-tenant-001"),
            agent_credential=os.environ.get("AGENTSHIELD_AGENT_CREDENTIAL", "agsh_demo_secret_credential_token"),
            backend_url=os.environ.get("AGENTSHIELD_BACKEND_URL", "http://localhost:8000"),
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            model_name=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            gemini_api_key=os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"),
            gemini_model=os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite"),
            openrouter_api_key=os.environ.get("OPENROUTER_API_KEY"),
            openrouter_model=os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct"),
            huggingface_api_key=os.environ.get("HUGGINGFACE_API_KEY") or os.environ.get("HF_TOKEN"),
            huggingface_model=os.environ.get("HUGGINGFACE_MODEL", "meta-llama/Llama-3.1-8B-Instruct"),
        )


settings = DemoSettings.load()
