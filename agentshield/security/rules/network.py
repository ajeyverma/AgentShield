"""
AgentShield AI — Network Domain Security Rules (Phase 4).
"""

from __future__ import annotations

import re
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, ToolCategory
from agentshield.security.rules.base import BaseRule, RuleMatchResult

# Cloud metadata services and local infrastructure IP addresses
_FORBIDDEN_NETWORK_PATTERNS = [
    re.compile(r"169\.254\.169\.254"),           # AWS/Azure/GCP metadata service
    re.compile(r"metadata\.google\.internal"),    # GCP internal metadata
    re.compile(r"100\.100\.100\.200"),           # Alibaba Cloud metadata
    re.compile(r"127\.0\.0\.1|localhost|0\.0\.0\.0", re.IGNORECASE),  # Loopback/local probing
]

_SUSPICIOUS_PORTS = {4444, 1337, 6667, 31337, 8888, 9999}


class NetworkMetadataServiceRule(BaseRule):
    """Blocks SSRF and access to cloud instance metadata services."""

    rule_id = "NET-001"
    name = "Block Cloud Metadata and Internal Loopback"
    description = "Blocks access to 169.254.169.254, cloud metadata endpoints, and loopback probing."

    def evaluate(self, request: ActionRequest) -> RuleMatchResult:
        is_net = (
            request.tool_category in (ToolCategory.NETWORK, ToolCategory.EXTERNAL_API, ToolCategory.BROWSER)
            or any(k in request.tool_name.lower() for k in ("http", "curl", "fetch", "request", "net", "url"))
        )
        if not is_net:
            return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)

        candidates = []
        if request.resource:
            candidates.append(request.resource)
        for key in ("url", "host", "endpoint", "uri", "ip", "address"):
            val = request.arguments.get(key)
            if isinstance(val, str):
                candidates.append(val)

        for dest in candidates:
            for pattern in _FORBIDDEN_NETWORK_PATTERNS:
                if pattern.search(dest):
                    return RuleMatchResult(
                        matched=True,
                        outcome=Decision.BLOCK,
                        reason=f"Access to prohibited internal/metadata destination is blocked: '{dest}'.",
                        rule_id=self.rule_id,
                        severity="CRITICAL",
                    )

            # Check port in URL if present
            port_match = re.search(r":(\d+)", dest)
            if port_match:
                port = int(port_match.group(1))
                if port in _SUSPICIOUS_PORTS:
                    return RuleMatchResult(
                        matched=True,
                        outcome=Decision.BLOCK,
                        reason=f"Connection to suspicious port {port} is blocked.",
                        rule_id=self.rule_id,
                        severity="HIGH",
                    )

        return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)
