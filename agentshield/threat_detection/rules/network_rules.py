"""
AgentShield AI — Network Threat Rules.
"""

from __future__ import annotations

import re

# Restricted protocols and schemes
SUSPICIOUS_SCHEMES = {"gopher", "dict", "ldap", "tftp", "file"}

# IP literals in URLs pattern
IP_IN_URL_PATTERN = re.compile(r":\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?")
