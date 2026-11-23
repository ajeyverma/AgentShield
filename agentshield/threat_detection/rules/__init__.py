"""
AgentShield AI — Threat Rules Package Export.
"""

from agentshield.threat_detection.rules.behavioral_rules import (
    EXFILTRATION_TOOL_SEQUENCE,
    MAX_CONSECUTIVE_DENIALS,
    MAX_REQUESTS_PER_MINUTE,
)
from agentshield.threat_detection.rules.command_rules import (
    CATASTROPHIC_PATTERNS,
    DEFENSE_EVASION_PATTERNS,
    ENCODED_EXECUTION_PATTERNS,
    PRIVILEGE_ESCALATION_PATTERNS,
    REVERSE_SHELL_PATTERNS,
)
from agentshield.threat_detection.rules.filesystem_rules import (
    DESTRUCTIVE_FS_OPERATIONS,
    RESTRICTED_SYSTEM_DIRS,
    TRAVERSAL_PATTERN,
)
from agentshield.threat_detection.rules.network_rules import (
    IP_IN_URL_PATTERN,
    SUSPICIOUS_SCHEMES,
)
from agentshield.threat_detection.rules.prompt_injection_rules import (
    DISCLOSURE_PATTERNS,
    EXFILTRATION_INSTRUCTION_PATTERNS,
    INJECTION_OVERRIDE_PATTERNS,
    ROLE_FORGERY_PATTERNS,
)
from agentshield.threat_detection.rules.sensitive_data_rules import (
    SENSITIVE_FIELD_NAMES,
    SENSITIVE_FILE_NAMES,
)

__all__ = [
    "INJECTION_OVERRIDE_PATTERNS",
    "DISCLOSURE_PATTERNS",
    "ROLE_FORGERY_PATTERNS",
    "EXFILTRATION_INSTRUCTION_PATTERNS",
    "SENSITIVE_FIELD_NAMES",
    "SENSITIVE_FILE_NAMES",
    "RESTRICTED_SYSTEM_DIRS",
    "TRAVERSAL_PATTERN",
    "DESTRUCTIVE_FS_OPERATIONS",
    "CATASTROPHIC_PATTERNS",
    "REVERSE_SHELL_PATTERNS",
    "PRIVILEGE_ESCALATION_PATTERNS",
    "DEFENSE_EVASION_PATTERNS",
    "ENCODED_EXECUTION_PATTERNS",
    "SUSPICIOUS_SCHEMES",
    "IP_IN_URL_PATTERN",
    "MAX_REQUESTS_PER_MINUTE",
    "MAX_CONSECUTIVE_DENIALS",
    "EXFILTRATION_TOOL_SEQUENCE",
]
