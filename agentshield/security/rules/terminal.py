"""
AgentShield AI — Terminal & Code Execution Domain Security Rules (Phase 4).
"""

from __future__ import annotations

import re
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, ToolCategory
from agentshield.security.rules.base import BaseRule, RuleMatchResult

# High-risk terminal and shell commands
_CRITICAL_COMMAND_PATTERNS = [
    re.compile(r"rm\s+-rf\s+[/~]", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:", re.IGNORECASE),  # fork bomb
    re.compile(r"mkfs|dd\s+if=", re.IGNORECASE),
    re.compile(r"chmod\s+-R\s+777", re.IGNORECASE),
    re.compile(r"(sudo|su\s+-|runas)\s+", re.IGNORECASE),
    re.compile(r"(nc|netcat|ncat)\s+.*-[e|c]\s+", re.IGNORECASE),  # reverse shell
    re.compile(r"/dev/(tcp|udp)/", re.IGNORECASE),
    re.compile(r"format\s+[a-z]:", re.IGNORECASE),
    re.compile(r"invoke-expression|iex\s+", re.IGNORECASE),
]


class TerminalDestructiveCommandRule(BaseRule):
    """Blocks catastrophic commands and requires approval for arbitrary shell execution."""

    rule_id = "TERM-001"
    name = "Guard Terminal & Shell Commands"
    description = "Blocks system-destructive commands and flags arbitrary terminal execution."

    def evaluate(self, request: ActionRequest) -> RuleMatchResult:
        is_term = (
            request.tool_category in (ToolCategory.TERMINAL, ToolCategory.CODE_EXECUTION)
            or any(k in request.tool_name.lower() for k in ("bash", "sh", "terminal", "shell", "exec", "cmd", "powershell"))
        )
        if not is_term:
            return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)

        command = request.arguments.get("command") or request.arguments.get("cmd") or request.resource or ""
        command_str = str(command).strip()

        # Check for catastrophic commands
        for pattern in _CRITICAL_COMMAND_PATTERNS:
            if pattern.search(command_str):
                return RuleMatchResult(
                    matched=True,
                    outcome=Decision.BLOCK,
                    reason=f"Catastrophic shell command pattern detected: prohibited execution.",
                    rule_id=self.rule_id,
                    severity="CRITICAL",
                )

        # Arbitrary shell execution requires human review by default
        return RuleMatchResult(
            matched=True,
            outcome=Decision.ASK_HUMAN,
            reason=f"Arbitrary terminal/shell execution requires human approval.",
            rule_id=self.rule_id,
            severity="HIGH",
            requires_approval=True,
        )
