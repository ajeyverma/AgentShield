"""
AgentShield AI — Security Rules Package Export.
"""

from agentshield.security.rules.base import BaseRule, RuleMatchResult
from agentshield.security.rules.data_access import DataAccessDestructiveSQLRule
from agentshield.security.rules.filesystem import (
    FilesystemDestructiveOperationRule,
    FilesystemSensitivePathRule,
)
from agentshield.security.rules.network import NetworkMetadataServiceRule
from agentshield.security.rules.terminal import TerminalDestructiveCommandRule

DEFAULT_RULES: list[BaseRule] = [
    FilesystemSensitivePathRule(),
    FilesystemDestructiveOperationRule(),
    NetworkMetadataServiceRule(),
    TerminalDestructiveCommandRule(),
    DataAccessDestructiveSQLRule(),
]

__all__ = [
    "BaseRule",
    "RuleMatchResult",
    "FilesystemSensitivePathRule",
    "FilesystemDestructiveOperationRule",
    "NetworkMetadataServiceRule",
    "TerminalDestructiveCommandRule",
    "DataAccessDestructiveSQLRule",
    "DEFAULT_RULES",
]
