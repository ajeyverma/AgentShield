# ==============================================================================
# AgentShield AI — Production Multi-Stage Dockerfile
# ==============================================================================

# Stage 1: Build & Dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY agentshield ./agentshield
COPY apps ./apps

RUN pip install --upgrade pip && \
    pip install greenlet email-validator python-multipart .[api]

# Stage 2: Minimal Runtime Environment
FROM python:3.11-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTSHIELD_ENV=remote \
    AGENTSHIELD_HOST=0.0.0.0 \
    AGENTSHIELD_PORT=8000 \
    AGENTSHIELD_LOG_FORMAT=json

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create secure non-root user and group
RUN groupadd -g 1001 agentshield && \
    useradd -u 1001 -g agentshield -s /bin/bash -m agentshield

# Copy installed site-packages and binaries from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source code
COPY agentshield ./agentshield
COPY apps ./apps
COPY demos ./demos
COPY scripts ./scripts
COPY alembic ./alembic
COPY alembic.ini pyproject.toml ./

# Ensure correct permissions for non-root execution
RUN mkdir -p /app/data /app/logs && \
    chown -R agentshield:agentshield /app

USER agentshield

EXPOSE 8000

# Healthcheck hitting versioned health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT:-8000}/api/v1/health || exit 1

CMD ["python", "scripts/start_server.py"]
