"""
AgentShield AI — Prompt Injection Detection Rules.
"""

from __future__ import annotations

import re

# Direct instruction overrides and jailbreak attempts
INJECTION_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|former)\s+(?:instructions|prompts|directives|guidelines)\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:rules|instructions|prompts)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbroken|god|unrestricted)\s+mode\b"),
    re.compile(r"(?i)\bdo\s+anything\s+now\b"),
    re.compile(r"(?i)\bforget\s+(?:everything\s+)?(?:you\s+were\s+told|all\s+prior\s+instructions)\b"),
    re.compile(r"(?i)\bfrom\s+now\s+on\s+you\s+(?:must|will)\s+act\s+as\b"),
]

# System prompt / secret disclosure attempts
DISCLOSURE_PATTERNS = [
    re.compile(r"(?i)\b(?:reveal|show|print|output|display|repeat|dump)\s+(?:the\s+)?(?:system\s+prompt|developer\s+prompt|initial\s+instructions|hidden\s+prompt)\b"),
    re.compile(r"(?i)\bwhat\s+(?:are|were)\s+your\s+(?:initial\s+instructions|system\s+instructions|core\s+prompts)\b"),
    re.compile(r"(?i)\b(?:print|leak|extract)\s+(?:your\s+)?(?:environment\s+variables|api\s+keys|credentials|passwords)\b"),
]

# Delimiter and system role forgery
ROLE_FORGERY_PATTERNS = [
    re.compile(r"(?i)(?:<\/?(?:system|developer|admin|root)>|\[SYSTEM\]|\[ADMIN\]|###\s*(?:System|Human|Assistant)\s*:)"),
    re.compile(r"(?i)\bNEW\s+ROLE\s*:\s*(?:SYSTEM|ADMINISTRATOR)\b"),
]

# Exfiltration instructions embedded in content
EXFILTRATION_INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)\b(?:send|post|transmit|exfiltrate|upload|forward)\s+(?:this|the|all)?\s*(?:data|keys|passwords|tokens|file)\s+to\s+(?:https?:\/\/|[0-9a-zA-Z\.-]+\.[a-zA-Z]{2,})"),
    re.compile(r"(?i)\bcurl\s+-X\s*POST\s+(?:https?:\/\/|\S+)\s+-d\b"),
]
