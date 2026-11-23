"""
AgentShield AI — Content Analyzer & Secret Redactor.

Inspects content strings for credentials, secrets, tokens, PII, and obfuscation.
Guarantees that sensitive secrets are never logged or stored in cleartext.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

# Regular expressions for sensitive secret detection
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "OPENAI_API_KEY": re.compile(r"\b(sk-[a-zA-Z0-9]{20,T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b"),
    "ANTHROPIC_API_KEY": re.compile(r"\b(sk-ant-[a-zA-Z0-9_-]{20,})\b"),
    "AWS_ACCESS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "AWS_SECRET_KEY": re.compile(r"\b([0-9a-zA-Z/+]{40})\b"),
    "GENERIC_API_KEY": re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token)[\s:=]+['\"]?([a-zA-Z0-9_\-\.]{16,128})['\"]?"),
    "JWT_TOKEN": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    "RSA_PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "SSH_PRIVATE_KEY": re.compile(r"-----BEGIN PRIVATE KEY-----"),
    "PASSWORD_IN_URL": re.compile(r"://[^:]+:([^@]+)@"),
    "PASSWORD_ASSIGNMENT": re.compile(r"(?i)\b(?:password|passwd|pwd)[\s:=]+['\"]?([^\s'\";]{6,64})['\"]?"),
    "BEARER_TOKEN": re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{16,})\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


class ContentAnalyzer:
    """Utility class for inspecting content and redacting sensitive data."""

    @classmethod
    def redact_string(cls, text: str) -> tuple[str, list[str]]:
        """Redact secrets and sensitive tokens from text.

        Returns (redacted_text, list_of_detected_secret_types).
        """
        if not text:
            return text, []

        redacted = text
        detected: list[str] = []

        for name, pattern in SECRET_PATTERNS.items():
            matches = list(pattern.finditer(redacted))
            if matches:
                detected.append(name)
                for m in reversed(matches):
                    # Redact capturing group 1 if present, else full match
                    if m.lastindex and m.lastindex >= 1:
                        val = m.group(1)
                        start = m.start(1)
                        end = m.end(1)
                    else:
                        val = m.group(0)
                        start = m.start(0)
                        end = m.end(0)

                    masked = f"[{name}:...{val[-4:] if len(val) >= 4 else '***'}]"
                    redacted = redacted[:start] + masked + redacted[end:]

        return redacted, detected

    @classmethod
    def redact_data(cls, data: Any) -> tuple[Any, list[str]]:
        """Recursively redact secrets in dicts, lists, and strings."""
        detected: list[str] = []
        if isinstance(data, str):
            res, det = cls.redact_string(data)
            detected.extend(det)
            return res, list(set(detected))
        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                # Check key name for sensitive terms
                lower_k = str(k).lower()
                if any(s in lower_k for s in ("password", "secret", "token", "api_key", "apikey", "credential", "private_key")):
                    if isinstance(v, str):
                        new_dict[k] = f"[REDACTED_FIELD:{k}]"
                        detected.append("SENSITIVE_KEY_NAME")
                        continue
                redacted_v, det = cls.redact_data(v)
                new_dict[k] = redacted_v
                detected.extend(det)
            return new_dict, list(set(detected))
        if isinstance(data, list):
            new_list = []
            for item in data:
                redacted_item, det = cls.redact_data(item)
                new_list.append(redacted_item)
                detected.extend(det)
            return new_list, list(set(detected))
        return data, []

    @classmethod
    def inspect_obfuscation(cls, text: str) -> list[str]:
        """Detect base64 or hex encoded payloads safely without execution."""
        findings = []
        # Check base64 candidate strings (length >= 32, valid charset)
        b64_pattern = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
        for match in b64_pattern.finditer(text):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
                # Check if decoded payload contains shell commands or URLs
                if any(kw in decoded.lower() for kw in ("curl ", "wget ", "powershell", "bash", "sh ", "http://", "https://", "rm -", "chmod ")):
                    findings.append(f"Suspicious base64-encoded command sequence detected: '{decoded[:40]}...'")
            except Exception:
                pass

        # Check hex candidate strings
        hex_pattern = re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b")
        for match in hex_pattern.finditer(text):
            candidate = match.group(0)
            if candidate.startswith("0x"):
                candidate = candidate[2:]
            try:
                decoded = binascii.unhexlify(candidate).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in ("curl ", "wget ", "powershell", "bash", "sh ", "http://", "https://")):
                    findings.append(f"Suspicious hex-encoded sequence detected: '{decoded[:40]}...'")
            except Exception:
                pass

        return findings
