"""
AgentShield AI — MCP Gateway Configuration (Phase 8).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class MCPGatewayConfig(BaseModel):
    """Configuration settings for the MCP Firewall Gateway."""

    # Transport / Process Launch Controls
    allowed_executables: set[str] = Field(
        default_factory=lambda: {"python", "python3", "node", "npx", "uvx", "docker"}
    )
    allow_custom_commands: bool = Field(
        default=False,
        description="Whether clients can supply custom executable paths (strictly forbidden in production)",
    )

    # SSRF / Network Controls
    blocked_ip_ranges: list[str] = Field(
        default_factory=lambda: [
            "0.0.0.0/8",         # "This host on this network"
            "10.0.0.0/8",        # RFC 1918 private network
            "100.64.0.0/10",     # Shared address space
            "127.0.0.0/8",       # Loopback
            "169.254.0.0/16",    # Link-local / AWS metadata
            "172.16.0.0/12",     # RFC 1918 private network
            "192.0.0.0/24",      # IETF Protocol Assignments
            "192.0.2.0/24",      # TEST-NET-1
            "192.88.99.0/24",    # 6to4 relay
            "192.168.0.0/16",    # RFC 1918 private network
            "198.18.0.0/15",     # Network benchmark tests
            "198.51.100.0/24",   # TEST-NET-2
            "203.0.113.0/24",    # TEST-NET-3
            "224.0.0.0/4",       # Multicast
            "240.0.0.0/4",       # Reserved
            "::1/128",           # IPv6 Loopback
            "::/128",            # IPv6 Unspecified
            "fc00::/7",          # IPv6 Unique Local
            "fe80::/10",         # IPv6 Link Local
        ]
    )

    # Size limits
    max_request_size_bytes: int = Field(default=10 * 1024 * 1024)  # 10MB
    max_response_size_bytes: int = Field(default=10 * 1024 * 1024)  # 10MB
    max_string_length: int = Field(default=1_000_000)

    # Timeouts
    default_timeout_seconds: float = Field(default=30.0)
    connect_timeout_seconds: float = Field(default=10.0)

    # Inspection toggles
    enable_redaction: bool = Field(default=True)
    enable_prompt_injection_inspection: bool = Field(default=True)
    enable_discovery_inspection: bool = Field(default=True)

    def is_executable_allowed(self, command: str) -> bool:
        """Check if executable binary is in the allowed whitelist."""
        if not command:
            return False
        base = os.path.basename(command).lower()
        if base.endswith(".exe"):
            base = base[:-4]
        return base in self.allowed_executables

    def validate_endpoint_url(self, url: str) -> tuple[bool, str]:
        """
        Validate remote HTTP/SSE endpoint against SSRF and blocked IP ranges.
        Returns (is_valid, reason).
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False, f"Unsupported scheme: {parsed.scheme}"

            hostname = parsed.hostname
            if not hostname:
                return False, "Missing hostname in endpoint URL"

            # Check for direct IP or resolve DNS
            try:
                ip_obj = ipaddress.ip_address(hostname)
                ips = [ip_obj]
            except ValueError:
                # Hostname requires resolution
                try:
                    resolved_info = socket.getaddrinfo(hostname, None)
                    ips = [ipaddress.ip_address(item[4][0]) for item in resolved_info]
                except Exception as e:
                    return False, f"Failed to resolve hostname '{hostname}': {e}"

            for ip in ips:
                for cidr in self.blocked_ip_ranges:
                    network = ipaddress.ip_network(cidr)
                    if ip in network:
                        return False, f"Target IP {ip} falls into blocked range {cidr} (SSRF protection)"

            return True, "Valid"
        except Exception as e:
            return False, f"URL validation failed: {e}"


# Global default configuration instance
default_mcp_gateway_config = MCPGatewayConfig()
