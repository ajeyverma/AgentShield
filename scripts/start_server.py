"""
AgentShield AI — Production Cloud Startup Script.

Reads dynamic PORT assigned by Railway / Render / cloud hosting and starts Uvicorn.
"""

from __future__ import annotations

import logging
import os
import sys

import uvicorn

if __name__ == "__main__":
    raw_port = os.getenv("PORT") or os.getenv("AGENTSHIELD_PORT") or "8000"
    try:
        port = int(raw_port)
    except ValueError:
        port = 8000

    host = os.getenv("AGENTSHIELD_HOST", "0.0.0.0")

    print(f"=== Starting AgentShield API on {host}:{port} ===")
    uvicorn.run(
        "apps.api.main:app",
        host=host,
        port=port,
        workers=1,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
