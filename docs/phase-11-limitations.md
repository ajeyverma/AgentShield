# Phase 11 Limitations & Operational Boundaries

## 1. Explicit Scope & Constraints

As established in Phase 11 requirements, the following boundaries and constraints apply:

### 1.1 Local vs Distributed Deployments
- Current metric collection uses thread-safe in-memory sliding windows. In horizontally-scaled multi-node backend deployments, metrics should be exported to Prometheus / OpenTelemetry collectors.
- SQLite is supported for local development and unit testing; PostgreSQL is required for high-concurrency production deployments.

### 1.2 Audit Log DBA Access Assumptions
- The cryptographic hash chain ($H_i = \text{SHA256}(\dots \parallel H_{i-1})$) mathematically proves that no standard user, service account, or API client has altered, deleted, or inserted records out of sequence.
- However, an adversary with direct superuser database access (DBA) could theoretically alter both the data and the stored hashes. To achieve true non-repudiation in adversarial environments, audit checkpoints should be exported to WORM cloud buckets (e.g. AWS S3 Object Lock, GCP Bucket Lock) or external distributed ledger services.

### 1.3 Desktop UI Boundaries
- All security enforcement, decision logic, and cryptographic verification remain strictly on the FastAPI backend.
- The PySide6 desktop application acts solely as an administrative interface and monitoring dashboard, consuming authoritative REST and WebSocket endpoints.
