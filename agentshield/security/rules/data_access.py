"""
AgentShield AI — Data Access & Database Domain Security Rules (Phase 4).
"""

from __future__ import annotations

import re
from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, ToolCategory
from agentshield.security.rules.base import BaseRule, RuleMatchResult

# Destructive SQL statements
_DESTRUCTIVE_SQL_PATTERNS = [
    re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW)\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+(TABLE)?\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\s+\w+\s*;?$", re.IGNORECASE),  # Unbounded DELETE
    re.compile(r"\bUPDATE\s+\w+\s+SET\s+[^;]+;?$", re.IGNORECASE),  # Potential unbounded UPDATE without WHERE
]


class DataAccessDestructiveSQLRule(BaseRule):
    """Requires approval for destructive database operations."""

    rule_id = "DB-001"
    name = "Guard Database Schema and Data Modifications"
    description = "Requires human review for DROP, TRUNCATE, and unbounded DELETE queries."

    def evaluate(self, request: ActionRequest) -> RuleMatchResult:
        is_db = (
            request.tool_category == ToolCategory.DATABASE
            or any(k in request.tool_name.lower() for k in ("sql", "query", "db", "database", "postgres", "sqlite"))
        )
        if not is_db:
            return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)

        query = request.arguments.get("query") or request.arguments.get("sql") or request.resource or ""
        query_str = str(query).strip()

        for pattern in _DESTRUCTIVE_SQL_PATTERNS:
            if pattern.search(query_str):
                return RuleMatchResult(
                    matched=True,
                    outcome=Decision.ASK_HUMAN,
                    reason=f"Destructive database query detected (schema modification or bulk deletion).",
                    rule_id=self.rule_id,
                    severity="CRITICAL",
                    requires_approval=True,
                )

        return RuleMatchResult(matched=False, outcome=Decision.ALLOW, reason="", rule_id=self.rule_id)
