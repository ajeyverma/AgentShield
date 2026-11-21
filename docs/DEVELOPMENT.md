# AgentShield AI — Development Guide

---

## Prerequisites

- Python 3.11 or higher
- Git
- (Optional) Docker & Docker Compose for containerized development
- (Optional) PostgreSQL for full production-equivalent local testing

---

## Environment Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (macOS / Linux)
source .venv/bin/activate

# Install all dependencies
pip install -e ".[all]"
```

---

## Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env — at minimum set:
# AGENTSHIELD_ENV=local
# AGENTSHIELD_SECRET_KEY=<generated key>
```

Generate a secret key:
```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

---

## Running the Backend

```bash
# Development mode (auto-reload on file changes)
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

# Or via the configured port in .env
python -m uvicorn apps.api.main:app --reload
```

Verify:
```bash
curl http://localhost:8000/api/v1/health
```

API docs available at: `http://localhost:8000/api/v1/docs`

---

## Running the Desktop Application

```bash
python apps/desktop/main.py
```

The desktop application starts independently of the backend. The backend URL is configured by `AGENTSHIELD_BACKEND_URL` in `.env`.

---

## Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=agentshield --cov-report=term-missing

# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# Security contract tests only
pytest tests/security/

# Specific test file
pytest tests/unit/test_action_contract.py -v
```

---

## Running with Docker

```bash
# Start backend + PostgreSQL
docker compose up --build

# Start in background
docker compose up -d

# View logs
docker compose logs -f api

# Stop
docker compose down
```

---

## Project Structure

```
agentshield-ai/
├── agentshield/          # Shared library (contracts, core, security modules)
│   ├── contracts/        # Pydantic models: ActionRequest, SecurityDecision, enums
│   ├── core/             # Configuration, logging, exceptions
│   ├── database/         # SQLAlchemy engine, session, base model
│   ├── integrations/     # Abstract integration interfaces
│   └── security/         # Policy, threat detection, risk (Phase 3+)
├── apps/
│   ├── api/              # FastAPI backend application
│   └── desktop/          # PySide6 desktop application
├── tests/
│   ├── unit/             # Contract and config tests
│   ├── integration/      # API endpoint tests
│   └── security/         # Security property tests
├── docs/                 # Architecture and design documentation
├── config/               # Environment configuration references
└── scripts/              # Utility scripts
```

---

## Code Style

```bash
# Lint and format check
ruff check .
ruff format --check .

# Auto-fix lint issues
ruff check --fix .
ruff format .

# Type checking
mypy agentshield/ apps/
```

---

## Adding a New API Route (Phase 2+ Reference)

1. Create `apps/api/routes/<feature>.py`
2. Define a `router = APIRouter(tags=["Feature"])` in the file
3. Add the router to `apps/api/main.py` via `app.include_router(...)`
4. Add integration tests in `tests/integration/test_<feature>.py`

---

## Database Migrations (Alembic — Phase 2+)

```bash
# Generate a migration after model changes
alembic revision --autogenerate -m "describe_change"

# Apply migrations
alembic upgrade head

# Downgrade one step
alembic downgrade -1
```

The Alembic configuration will be added to `agentshield/database/migrations/` in Phase 2.
