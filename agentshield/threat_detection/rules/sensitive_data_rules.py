"""
AgentShield AI — Sensitive Data Rules.
"""

from __future__ import annotations

import re

# Keywords indicating sensitive data context
SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "access_token", "auth_token", "private_key", "certificate",
    "id_rsa", "session_token", "credit_card", "ssn", "credentials",
}

# High-risk target paths containing secrets
SENSITIVE_FILE_NAMES = [
    re.compile(r"(?i)\.env(?:\..*)?$"),
    re.compile(r"(?i)id_rsa(?:|\.pub)$"),
    re.compile(r"(?i)credentials(?:\.json|\.xml)?$"),
    re.compile(r"(?i)secrets?\.(?:json|ya?ml|properties|toml)$"),
    re.compile(r"(?i)\.aws\/(?:credentials|config)$"),
    re.compile(r"(?i)\.ssh\/(?:id_rsa|id_ed25519|authorized_keys)$"),
]
