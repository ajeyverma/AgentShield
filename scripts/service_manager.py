"""
AgentShield AI — Local Service Lifecycle Manager.

Manages starting, stopping, restarting, inspecting, and monitoring the
AgentShield FastAPI backend process on local host systems.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

from agentshield.core.config import settings

PID_FILE = Path(".agentshield_backend.pid")
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "backend.log"


def is_process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            output = subprocess.check_output(["tasklist", "/fi", f"PID eq {pid}"], text=True)
            return str(pid) in output
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def get_active_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
        if is_process_running(pid):
            return pid
        PID_FILE.unlink(missing_ok=True)
        return None
    except Exception:
        return None


def start_service(host: str | None = None, port: int | None = None):
    active = get_active_pid()
    if active:
        print(f"AgentShield backend is already running (PID: {active}).")
        return

    h = host or settings.host
    p = port or settings.port
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Starting AgentShield backend on {h}:{p}...")
    log_handle = open(LOG_FILE, "a", encoding="utf-8")

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "apps.api.main:app",
        "--host",
        h,
        "--port",
        str(p),
        "--log-level",
        "info",
    ]

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

    proc = subprocess.Popen(
        cmd,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
        cwd=str(Path.cwd()),
    )

    PID_FILE.write_text(str(proc.pid))
    print(f"Backend process spawned (PID: {proc.pid}). Waiting for health check...")

    # Wait up to 10 seconds for healthy status
    start_time = time.time()
    url = f"http://{'127.0.0.1' if h == '0.0.0.0' else h}:{p}/api/v1/health"
    healthy = False

    while time.time() - start_time < 10.0:
        time.sleep(0.5)
        try:
            resp = httpx.get(url, timeout=1.0)
            if resp.status_code == 200:
                healthy = True
                break
        except Exception:
            pass

    if healthy:
        print(f"✓ AgentShield backend is operational at: http://{h}:{p}")
        print(f"Logs directed to: {LOG_FILE}")
    else:
        print(f"⚠ Backend process {proc.pid} started, but healthcheck at {url} timed out.")
        print(f"Check logs for details: {LOG_FILE}")


def stop_service():
    pid = get_active_pid()
    if not pid:
        print("AgentShield backend is not currently running.")
        return

    print(f"Stopping AgentShield backend (PID: {pid})...")
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

    PID_FILE.unlink(missing_ok=True)
    print("✓ Backend service stopped.")


def service_status():
    pid = get_active_pid()
    url = f"{settings.backend_url}/api/v1/health"

    print("=" * 60)
    print("AgentShield AI — Service Status")
    print(f"Process PID:    {pid if pid else 'NOT RUNNING'}")
    print(f"Backend URL:    {settings.backend_url}")
    print(f"Health Endpoint: {url}")

    if not pid:
        print("Service Status: STOPPED")
        print("=" * 60)
        return

    try:
        t0 = time.perf_counter()
        resp = httpx.get(url, timeout=2.0)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        if resp.status_code == 200:
            data = resp.json()
            print("Service Status: HEALTHY (Online)")
            print(f"Response Time:  {latency_ms:.1f}ms")
            print(f"Status Data:    {data}")
        else:
            print(f"Service Status: DEGRADED (HTTP {resp.status_code})")
    except Exception as exc:
        print(f"Service Status: UNRESPONSIVE ({exc})")
    print("=" * 60)


def view_logs(lines: int = 50):
    if not LOG_FILE.exists():
        print(f"No log file found at {LOG_FILE}")
        return
    print(f"--- Tail of {LOG_FILE} ({lines} lines) ---")
    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
        for line in all_lines[-lines:]:
            print(line, end="")


def main():
    parser = argparse.ArgumentParser(description="AgentShield Service Lifecycle Manager")
    parser.add_argument("action", choices=["start", "stop", "restart", "status", "logs"], help="Lifecycle action")
    parser.add_argument("--host", default=None, help="Host to bind to")
    parser.add_argument("--port", type=int, default=None, help="Port to bind to")
    parser.add_argument("--lines", type=int, default=50, help="Number of log lines to show")
    args = parser.parse_args()

    if args.action == "start":
        start_service(args.host, args.port)
    elif args.action == "stop":
        stop_service()
    elif args.action == "restart":
        stop_service()
        time.sleep(1)
        start_service(args.host, args.port)
    elif args.action == "status":
        service_status()
    elif args.action == "logs":
        view_logs(args.lines)


if __name__ == "__main__":
    main()
