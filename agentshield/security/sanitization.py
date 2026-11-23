"""
AgentShield AI — Secret Sanitization and Redaction Utility (Phase 10).

Provides recursive redaction of sensitive tokens, passwords, keys, and credentials
from JSON payloads, execution arguments, audit logs, and WebSocket broadcasts.
"""

from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"auth(orization)?", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"bearer", re.IGNORECASE),
    re.compile(r"access[_-]?token", re.IGNORECASE),
]

SENSITIVE_VALUE_REGEXES = [
    re.compile(r"bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9]{20,}", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]{30,}", re.IGNORECASE),
    re.compile(r"ash_[A-Za-z0-9\-_]{30,}", re.IGNORECASE),
    re.compile(r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", re.IGNORECASE),
]

REDACTED_STR = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    """Check if key name implies sensitive data."""
    if not isinstance(key, str):
        return False
    return any(p.search(key) for p in SENSITIVE_KEY_PATTERNS)


def redact_sensitive_string(val: str) -> str:
    """Scan and redact any embedded secrets (e.g., API keys, Bearer tokens) in strings."""
    if not isinstance(val, str):
        return val
    result = val
    for regex in SENSITIVE_VALUE_REGEXES:
        result = regex.sub(REDACTED_STR, result)
    return result


def redact_secrets(data: Any) -> Any:
    """Recursively scrub secrets from dictionaries, lists, strings, and primitives.

    Returns a deep copy with sensitive values sanitized.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if is_sensitive_key(str(k)):
                sanitized[k] = REDACTED_STR
            else:
                sanitized[k] = redact_secrets(v)
        return sanitized
    elif isinstance(data, list):
        return [redact_secrets(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(redact_secrets(item) for item in data)
    elif isinstance(data, set):
        return {redact_secrets(item) for item in data}
    elif isinstance(data, str):
        return redact_sensitive_string(data)
    else:
        return data
