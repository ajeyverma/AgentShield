"""
AgentShield AI — Production Cloud Startup Script.

Reads dynamic PORT assigned by Railway / Render / cloud hosting and starts Uvicorn.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading

import uvicorn


def _start_port_forwarder(from_port: int, to_port: int) -> None:
    """Forward TCP traffic from an alternate port so Railway/Docker never 502s."""
    if from_port == to_port:
        return

    def forward_stream(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(8192)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                src.close()
            except Exception:
                pass
            try:
                dst.close()
            except Exception:
                pass

    def handle_client(client_sock: socket.socket) -> None:
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect(("127.0.0.1", to_port))
            t1 = threading.Thread(target=forward_stream, args=(client_sock, target_sock), daemon=True)
            t2 = threading.Thread(target=forward_stream, args=(target_sock, client_sock), daemon=True)
            t1.start()
            t2.start()
        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass

    def listen_loop() -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", from_port))
            srv.listen(128)
            print(f"[PortBridge] Forwarding incoming requests on {from_port} -> {to_port}", flush=True)
            while True:
                client, _ = srv.accept()
                threading.Thread(target=handle_client, args=(client,), daemon=True).start()
        except Exception as exc:
            print(f"[PortBridge] Optional bridge on port {from_port} not bound: {exc}", flush=True)

    thread = threading.Thread(target=listen_loop, daemon=True)
    thread.start()


if __name__ == "__main__":
    app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if app_root not in sys.path:
        sys.path.insert(0, app_root)

    raw_port = os.getenv("PORT") or os.getenv("AGENTSHIELD_PORT") or "8000"
    try:
        port = int(raw_port)
    except ValueError:
        port = 8000

    host = os.getenv("AGENTSHIELD_HOST", "0.0.0.0")

    # Start bridges on standard ports so both 8000 and 8080 respond
    alt_port = 8000 if port == 8080 else 8080
    _start_port_forwarder(from_port=alt_port, to_port=port)

    print(f"=== Starting AgentShield API on {host}:{port} (Dual-Port Bridge on {alt_port}) ===", flush=True)
    uvicorn.run(
        "apps.api.main:app",
        host=host,
        port=port,
        workers=1,
        log_level="info",
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
