"""
AgentShield AI — Action Analyzer.

Extracts normalized resource targets, operation types, and parameter semantics
from an ActionRequest for threat evaluation.
"""

from __future__ import annotations

import os
from typing import Any

from agentshield.contracts.action import ActionRequest


class ActionAnalyzer:
    """Helper to inspect and normalize request attributes."""

    @classmethod
    def extract_target_resource(cls, request: ActionRequest) -> str:
        """Extract or infer the principal resource target."""
        if request.resource:
            return request.resource.strip()

        args = request.arguments or {}
        for key in ("path", "file", "filepath", "url", "destination", "host", "command", "cmd", "query", "table"):
            if key in args and isinstance(args[key], str) and args[key].strip():
                return args[key].strip()

        return ""

    @classmethod
    def extract_string_payloads(cls, data: Any) -> list[str]:
        """Flatten all string values in arguments for textual threat analysis."""
        strings: list[str] = []
        if isinstance(data, str):
            strings.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                strings.extend(cls.extract_string_payloads(v))
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                strings.extend(cls.extract_string_payloads(item))
        return strings
