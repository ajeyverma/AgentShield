"""
AgentShield AI — Behavioral Threat Rules & Thresholds.
"""

from __future__ import annotations

# Maximum permitted requests in a 60-second window before anomaly flag
MAX_REQUESTS_PER_MINUTE = 30

# Maximum consecutive denied/blocked actions before lockout/alert
MAX_CONSECUTIVE_DENIALS = 3

# High-risk tool sequence detection: reading files followed by outbound network
EXFILTRATION_TOOL_SEQUENCE = ("read_file", "http_post")
