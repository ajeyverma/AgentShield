"""
AgentShield AI — Policy Engine & Domain Rules Unit Tests (Phase 4).
"""

from __future__ import annotations

import json
import uuid

from agentshield.contracts.action import ActionRequest
from agentshield.contracts.enums import Decision, IntegrationType, ToolCategory
from agentshield.database.models.policy import Policy
from agentshield.security.policy_engine import PolicyEngine


def _req(tool="read_file", cat=ToolCategory.FILE_SYSTEM, op="read", resource=None, args=None):
    return ActionRequest(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        integration_type=IntegrationType.SDK_OPENAI,
        tool_name=tool,
        tool_category=cat,
        operation=op,
        resource=resource,
        arguments=args or {},
    )


class TestPolicyEngine:
    def test_domain_rule_blocks_sensitive_file(self):
        engine = PolicyEngine()
        req = _req(resource="/etc/passwd")
        res = engine.evaluate(req, db_policies=[])
        assert res.decision == Decision.BLOCK
        assert any("protected system path" in r for r in res.reasons)

    def test_domain_rule_blocks_path_traversal(self):
        engine = PolicyEngine()
        req = _req(resource="../../secret.txt")
        res = engine.evaluate(req, db_policies=[])
        assert res.decision == Decision.BLOCK
        assert any("Path traversal" in r for r in res.reasons)

    def test_domain_rule_blocks_cloud_metadata_ssrf(self):
        engine = PolicyEngine()
        req = _req(
            tool="http_client",
            cat=ToolCategory.NETWORK,
            op="get",
            args={"url": "http://169.254.169.254/latest/meta-data"},
        )
        res = engine.evaluate(req, db_policies=[])
        assert res.decision == Decision.BLOCK
        assert any("metadata destination" in r for r in res.reasons)

    def test_domain_rule_blocks_destructive_terminal_command(self):
        engine = PolicyEngine()
        req = _req(
            tool="bash",
            cat=ToolCategory.TERMINAL,
            op="exec",
            args={"command": "rm -rf /"},
        )
        res = engine.evaluate(req, db_policies=[])
        assert res.decision == Decision.BLOCK
        assert any("Catastrophic shell command" in r for r in res.reasons)

    def test_domain_rule_requires_approval_for_file_deletion(self):
        engine = PolicyEngine()
        req = _req(
            tool="file_delete",
            cat=ToolCategory.FILE_SYSTEM,
            op="delete",
            resource="/home/user/docs/old.pdf",
        )
        res = engine.evaluate(req, db_policies=[])
        assert res.decision == Decision.ASK_HUMAN
        assert res.requires_approval is True

    def test_user_policy_block_precedence(self):
        engine = PolicyEngine()
        pol = Policy(
            id=str(uuid.uuid4()),
            user_id="user-1",
            name="Block Curl Tool",
            category="network",
            enforcement_mode="enforce",
            is_enabled=True,
            rules_json=json.dumps({"tools": ["curl*"], "outcome": "BLOCK", "reason": "No curl permitted"}),
        )
        req = _req(tool="curl_fetch", cat=ToolCategory.NETWORK)
        res = engine.evaluate(req, db_policies=[pol])
        assert res.decision == Decision.BLOCK
        assert any("No curl permitted" in r for r in res.reasons)

    def test_user_policy_monitor_mode_does_not_block(self):
        engine = PolicyEngine()
        pol = Policy(
            id=str(uuid.uuid4()),
            user_id="user-1",
            name="Monitor SQL",
            category="database",
            enforcement_mode="monitor",
            is_enabled=True,
            rules_json=json.dumps({"tools": ["sql_*"], "outcome": "BLOCK"}),
        )
        req = _req(tool="sql_query", cat=ToolCategory.DATABASE, op="select")
        res = engine.evaluate(req, db_policies=[pol])
        assert res.decision == Decision.ALLOW
        assert any("MONITOR mode" in r for r in res.reasons)
