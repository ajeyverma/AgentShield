# AgentShield AI — Database Management & Migrations

AgentShield uses **SQLAlchemy 2.0** with **Alembic** for schema migrations, supporting both PostgreSQL (production) and SQLite (development).

---

## 1. Database Architecture & Schema

The core schema includes:
- **`agents`**: Agent identity, tenant linkage, status, allowed tools.
- **`policies`**: Priority-ordered declarative security rules.
- **`audit_events`**: Cryptographically hash-chained event records.
- **`approvals`**: HITL pending approval requests and decisions.
- **`users`**: Administrative and analyst accounts with Argon2 password hashes.
- **`tools`**: Registered tools and adapter bindings.

---

## 2. Automated Migration Management (`scripts/db_init.py`)

AgentShield provides an automated database migration script that ensures zero manual migration drift.

### Check Current Migration Status
```bash
python scripts/db_init.py --status
```
Example Output:
```
[INFO] Current Migration Revision: 8f1a2b3c4d5e (HEAD)
[INFO] Database is fully up to date.
```

### Apply Pending Migrations to Head
```bash
python scripts/db_init.py
```

---

## 3. Creating New Schema Migrations

When modifying SQLAlchemy models in `agentshield/models/`:

```bash
# Generate new migration script
python -m alembic revision --autogenerate -m "describe_schema_change"

# Review the generated file in alembic/versions/
# Apply the migration
python scripts/db_init.py
```
