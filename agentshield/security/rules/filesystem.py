"""
AgentShield AI — Filesystem Domain Security Rules (Phase 4).
"""

from __future__ import annotations

import re
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, ToolCategory
from agentshield.security.rules.base import BaseRule, RuleMatchResult

# Critical system and credential paths across Linux, macOS, and Windows
_RESTRICTED_PATH_PATTERNS = [
    re.compile(r"(^|[/\\])\.env($|[/\\])", re.IGNORECASE),
    re.compile(r"(^|[/\\])\.ssh[/\\]", re.IGNORECASE),
    re.compile(r"id_rsa|id_ed25519|id_ecdsa", re.IGNORECASE),
    re.compile(r"(^|[/\\])\.aws[/\\]credentials", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|sudoers|master\.passwd)", re.IGNORECASE),
    re.compile(r"[a-z]:\\windows\\system32\\config", re.IGNORECASE),
    re.compile(r"[a-z]:\\windows\\system32\\sam", re.IGNORECASE),
    re.compile(r"/etc/security", re.IGNORECASE),
]

_DESTRUCTIVE_OPS = {"delete", "remove", "unlink", "rmdir", "destroy", "purge", "erase"}


class FilesystemSensitivePathRule(BaseRule):
    """Blocks access to sensitive credentials, system configuration, and keys."""

    rule_id = "FS-001"
    name = "Block Sensitive Path Access"
    description = "Prevents reading or modifying private keys, .env secrets, or OS system files."

    def evaluate(self, request: ActionRequest) -> RuleMatchResult:
        # Check resource and path in arguments
        candidates = []
        if request.resource:
            candidates.append(request.resource)
        for key in ("path", "file", "filepath", "filename", "destination", "source"):
            val = request.arguments.get(key)
            if isinstance(val, str):
                candidates.append(val)

        for path_str in candidates:
            # Check path traversal
            if "../" in path_str or "..\\" in path_str:
                return RuleMatchResult(
                    matched=True,
                    outcome=Decision.BLOCK,
                    reason=f"Path traversal sequence detected in filesystem request: '{path_str}'.",
                    rule_id=self.rule_id,
                    severity="CRITICAL",
                )
            for pattern in _RESTRICTED_PATH_PATTERNS:
                if pattern.search(path_str):
                    return RuleMatchResult(
                        matched=True,
                        outcome=Decision.BLOCK,
                        reason=f"Access to protected system path or secret file is prohibited: '{path_str}'.",
                        rule_id=self.rule_id,
                        severity="CRITICAL",
                    )

        return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)


class FilesystemDestructiveOperationRule(BaseRule):
    """Requires human approval for destructive filesystem operations."""

    rule_id = "FS-002"
    name = "Require Approval for File Deletion"
    description = "Forces human verification before deleting or removing files."

    def evaluate(self, request: ActionRequest) -> RuleMatchResult:
        is_fs = request.tool_category == ToolCategory.FILE_SYSTEM or "file" in request.tool_name.lower()
        if not is_fs:
            return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)

        op = (request.operation or "").lower().strip()
        tool = request.tool_name.lower()
        if op in _DESTRUCTIVE_OPS or any(d in tool for d in ("delete", "remove", "unlink")):
            target = request.resource or request.arguments.get("path") or "unspecified target"
            return RuleMatchResult(
                matched=True,
                outcome=Decision.ASK_HUMAN,
                reason=f"File deletion or destructive operation on '{target}' requires human approval.",
                rule_id=self.rule_id,
                severity="HIGH",
                requires_approval=True,
            )

        return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)
