"""
AgentShield AI — Dangerous Command Rules.
"""

from __future__ import annotations

import re

CATASTROPHIC_PATTERNS = [
    re.compile(r"(?i)\brm\s+-(?:r|rf|fr)\s+(?:\/|\/\*|~\/|~|\$HOME)(?:\s|$|;|\*|\b)"),
    re.compile(r"(?i)\brmdir\s+\/s\s+\/q\s+[c-zC-Z]:\\(?:\s|$|;|\*|\b)"),
    re.compile(r"(?i)\bformat\s+[c-zC-Z]:\s*\/fs"),
    re.compile(r"(?i)\bmkfs(?:\.\w+)?\s+\/dev\/"),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),  # fork bomb
    re.compile(r"(?i)\bdd\s+if=\/dev\/(?:zero|urandom)\s+of=\/dev\/[sh]d[a-z]\b"),
]

REVERSE_SHELL_PATTERNS = [
    re.compile(r"(?i)\bnc\s+(?:-e|--exec)\s+\/(?:bin|usr)\/(?:sh|bash)\b"),
    re.compile(r"(?i)\bbash\s+-i\s+>&?\s*\/dev\/tcp\/\d{1,3}\.\d{1,3}"),
    re.compile(r"(?i)\bmkfifo\s+\/tmp\/\w+\s*;\s*(?:nc|cat)\b"),
    re.compile(r"(?i)\bpython(?:\d)?\s+-c\s+['\"].*import\s+socket.*subprocess\.call\(['\"]\/bin\/(?:sh|bash)['\"]"),
]

PRIVILEGE_ESCALATION_PATTERNS = [
    re.compile(r"(?i)\bsudo\s+(?:su|bash|sh|-i)\b"),
    re.compile(r"(?i)\bchmod\s+(?:-R\s+)?777\s+(?:\/|\/etc|\/bin|\/usr)\b"),
    re.compile(r"(?i)\bnet\s+localgroup\s+administrators\s+\S+\s+\/add\b"),
    re.compile(r"(?i)\bchown\s+(?:-R\s+)?root\b"),
]

DEFENSE_EVASION_PATTERNS = [
    re.compile(r"(?i)\b(?:setenforce\s+0|systemctl\s+stop\s+firewalld)\b"),
    re.compile(r"(?i)\biptables\s+-F\b"),
    re.compile(r"(?i)\bsc\s+stop\s+(?:WinDefend|MpsSvc)\b"),
    re.compile(r"(?i)\bnetsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off\b"),
]

ENCODED_EXECUTION_PATTERNS = [
    re.compile(r"(?i)\bpowershell(?:\.exe)?\s+.*-(?:enc|encodedcommand)\s+[a-zA-Z0-9+/=]{16,}\b"),
    re.compile(r"(?i)\becho\s+[a-zA-Z0-9+/=]{16,}\s*\|\s*base64\s+-d\s*\|\s*(?:bash|sh)\b"),
]
