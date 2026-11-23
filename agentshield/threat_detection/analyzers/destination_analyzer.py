"""
AgentShield AI — Destination Analyzer.

Parses and inspects URLs, IP addresses, domains, and ports for SSRF,
cloud metadata access, and unauthorized data egress.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# Cloud metadata endpoints
CLOUD_METADATA_IPS = {"169.254.169.254"}
CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
}

# Suspicious egress ports (e.g. IRC, telnet, smb, rdp, shell listener)
SUSPICIOUS_PORTS = {21, 23, 25, 135, 137, 138, 139, 445, 1080, 1433, 1434, 1521, 3306, 3389, 4444, 5432, 6667, 8888, 9001}


class DestinationAnalysis:
    """Structured result of network destination inspection."""

    def __init__(
        self,
        raw_target: str,
        parsed_url: str | None,
        hostname: str,
        port: int | None,
        is_ip_literal: bool,
        is_loopback: bool,
        is_private: bool,
        is_cloud_metadata: bool,
        is_suspicious_port: bool,
        anomalies: list[str],
    ) -> None:
        self.raw_target = raw_target
        self.parsed_url = parsed_url
        self.hostname = hostname
        self.port = port
        self.is_ip_literal = is_ip_literal
        self.is_loopback = is_loopback
        self.is_private = is_private
        self.is_cloud_metadata = is_cloud_metadata
        self.is_suspicious_port = is_suspicious_port
        self.anomalies = anomalies


class DestinationAnalyzer:
    """Static analysis of network targets and destinations."""

    @classmethod
    def analyze_destination(cls, target: str) -> DestinationAnalysis:
        anomalies: list[str] = []
        parsed = None
        hostname = ""
        port = None

        # Check if URL
        if "://" in target:
            try:
                parsed = urlparse(target)
                hostname = parsed.hostname or ""
                port = parsed.port
            except Exception:
                anomalies.append(f"Invalid URL structure: '{target}'")
        else:
            # Maybe host:port
            if ":" in target and not target.endswith("]"):
                parts = target.split(":")
                hostname = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    pass
            else:
                hostname = target

        hostname = hostname.strip().lower()

        is_ip_literal = False
        is_loopback = False
        is_private = False
        is_cloud_metadata = False

        if hostname in CLOUD_METADATA_HOSTS:
            is_cloud_metadata = True
            anomalies.append(f"Cloud metadata endpoint detected: '{hostname}'")

        if hostname in ("localhost", "ip6-localhost", "ip6-loopback"):
            is_loopback = True
            anomalies.append(f"Local loopback hostname detected: '{hostname}'")

        # Check if IP literal
        try:
            ip_obj = ipaddress.ip_address(hostname)
            is_ip_literal = True
            if ip_obj.is_loopback:
                is_loopback = True
                anomalies.append(f"Loopback IP address requested: '{hostname}'")
            if ip_obj.is_private:
                is_private = True
                anomalies.append(f"Private RFC1918/RFC4193 IP address requested: '{hostname}'")
            if str(ip_obj) in CLOUD_METADATA_IPS or ip_obj.is_link_local:
                is_cloud_metadata = True
                anomalies.append(f"Link-local / Cloud metadata IP requested: '{hostname}'")
        except ValueError:
            # Not an IP literal
            pass

        is_suspicious_port = False
        if port and port in SUSPICIOUS_PORTS:
            is_suspicious_port = True
            anomalies.append(f"Unusual or suspicious network egress port: {port}")

        return DestinationAnalysis(
            raw_target=target,
            parsed_url=str(parsed) if parsed else None,
            hostname=hostname,
            port=port,
            is_ip_literal=is_ip_literal,
            is_loopback=is_loopback,
            is_private=is_private,
            is_cloud_metadata=is_cloud_metadata,
            is_suspicious_port=is_suspicious_port,
            anomalies=anomalies,
        )
