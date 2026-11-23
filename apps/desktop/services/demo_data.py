"""
AgentShield AI — Centralized Demo Data Provider (Phase 2).

ALL pages pull their sample records from this module.
Totals shown on the Dashboard are computed directly from these lists
so statistics always match the detail tables.

⚠️  DEMO DATA — Not representative of real security monitoring.
    Replace with real backend service calls in Phase 3+.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _dt(minutes_ago: int) -> str:
    """Return an ISO-formatted UTC timestamp N minutes in the past."""
    t = datetime(2026, 11, 23, 10, 0, 0) - timedelta(minutes=minutes_ago)
    return t.strftime("%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# Agents
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentRecord:
    agent_id: str
    name: str
    framework: str
    status: str          # "Active" | "Idle" | "Disconnected" | "Error"
    last_seen: str
    tools_registered: int
    risk_status: str     # "Normal" | "Elevated" | "High" | "Critical"
    total_actions: int
    blocked_actions: int
    description: str = ""


AGENTS: list[AgentRecord] = [
    AgentRecord(
        agent_id="agt-0001",
        name="ResearchAgent-GPT4",
        framework="OpenAI Agents SDK",
        status="Active",
        last_seen=_dt(2),
        tools_registered=8,
        risk_status="Normal",
        total_actions=142,
        blocked_actions=3,
        description="Performs web research and document summarisation tasks.",
    ),
    AgentRecord(
        agent_id="agt-0002",
        name="DataPipeline-Claude",
        framework="Claude Agent SDK",
        status="Active",
        last_seen=_dt(5),
        tools_registered=12,
        risk_status="Elevated",
        total_actions=289,
        blocked_actions=18,
        description="Runs ETL pipelines and writes results to the data warehouse.",
    ),
    AgentRecord(
        agent_id="agt-0003",
        name="CustomerSupport-LG",
        framework="LangGraph",
        status="Idle",
        last_seen=_dt(45),
        tools_registered=5,
        risk_status="Normal",
        total_actions=78,
        blocked_actions=1,
        description="Handles tier-1 customer support ticket triage.",
    ),
    AgentRecord(
        agent_id="agt-0004",
        name="DevOpsOrchestrator",
        framework="CrewAI",
        status="Active",
        last_seen=_dt(1),
        tools_registered=15,
        risk_status="High",
        total_actions=412,
        blocked_actions=37,
        description="Coordinates CI/CD pipeline tasks and infrastructure changes.",
    ),
    AgentRecord(
        agent_id="agt-0005",
        name="SecurityScanner",
        framework="Custom Python Agent",
        status="Idle",
        last_seen=_dt(120),
        tools_registered=6,
        risk_status="Normal",
        total_actions=56,
        blocked_actions=0,
        description="Scheduled vulnerability scanning agent.",
    ),
    AgentRecord(
        agent_id="agt-0006",
        name="ContentGenerator-ADK",
        framework="Google ADK",
        status="Disconnected",
        last_seen=_dt(480),
        tools_registered=4,
        risk_status="Normal",
        total_actions=33,
        blocked_actions=2,
        description="Generates marketing content drafts.",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Activity records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ActivityRecord:
    record_id: str
    timestamp: str
    agent_name: str
    agent_id: str
    tool_name: str
    operation: str
    decision: str      # "ALLOW" | "BLOCK" | "ASK_HUMAN"
    risk_level: str    # "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    status: str        # "Completed" | "Blocked" | "Pending Approval" | "Failed"
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


ACTIVITY: list[ActivityRecord] = [
    ActivityRecord("act-001", _dt(1),  "ResearchAgent-GPT4",   "agt-0001", "web_search",    "search",    "ALLOW",     "LOW",      "Completed",        {"query": "AI security best practices 2026"}, "Routine web search within allowed policy."),
    ActivityRecord("act-002", _dt(2),  "DataPipeline-Claude",  "agt-0002", "read_file",     "read",      "ALLOW",     "LOW",      "Completed",        {"path": "/data/reports/q4_2026.csv"},        "File read from approved data directory."),
    ActivityRecord("act-003", _dt(3),  "DevOpsOrchestrator",   "agt-0004", "execute_cmd",   "run",       "ASK_HUMAN", "HIGH",     "Pending Approval", {"cmd": "kubectl rollout restart deployment/api"}, "Infrastructure change requires human approval."),
    ActivityRecord("act-004", _dt(4),  "DataPipeline-Claude",  "agt-0002", "send_email",    "send",      "BLOCK",     "MEDIUM",   "Blocked",          {"to": "external@unknown.com", "subject": "Q4 Report"}, "Email to unrecognised external domain blocked."),
    ActivityRecord("act-005", _dt(6),  "ResearchAgent-GPT4",   "agt-0001", "read_file",     "read",      "ALLOW",     "NONE",     "Completed",        {"path": "/tmp/cache/search_results.json"},   "Temporary cache read, no risk."),
    ActivityRecord("act-006", _dt(8),  "DevOpsOrchestrator",   "agt-0004", "write_file",    "write",     "ALLOW",     "LOW",      "Completed",        {"path": "/var/log/deploy.log"},              "Log write within allowed path."),
    ActivityRecord("act-007", _dt(10), "CustomerSupport-LG",   "agt-0003", "query_db",      "select",    "ALLOW",     "NONE",     "Completed",        {"table": "tickets", "limit": 50},            "Read-only DB query within policy."),
    ActivityRecord("act-008", _dt(12), "DataPipeline-Claude",  "agt-0002", "delete_file",   "delete",    "BLOCK",     "HIGH",     "Blocked",          {"path": "/data/archive/2025_backup.tar"},    "Deletion of backup data prohibited by policy."),
    ActivityRecord("act-009", _dt(15), "DevOpsOrchestrator",   "agt-0004", "call_api",      "post",      "ASK_HUMAN", "MEDIUM",   "Pending Approval", {"url": "https://api.stripe.com/charges"},    "Payment API call requires approval."),
    ActivityRecord("act-010", _dt(18), "SecurityScanner",      "agt-0005", "read_file",     "read",      "ALLOW",     "NONE",     "Completed",        {"path": "/etc/os-release"},                  "Safe OS version check."),
    ActivityRecord("act-011", _dt(20), "ResearchAgent-GPT4",   "agt-0001", "browse_web",    "navigate",  "ALLOW",     "LOW",      "Completed",        {"url": "https://arxiv.org/abs/2401.00001"},  "Academic paper fetch."),
    ActivityRecord("act-012", _dt(22), "DataPipeline-Claude",  "agt-0002", "write_file",    "write",     "ALLOW",     "LOW",      "Completed",        {"path": "/data/output/processed_q4.parquet"},"Output write to approved directory."),
    ActivityRecord("act-013", _dt(25), "DevOpsOrchestrator",   "agt-0004", "execute_cmd",   "run",       "BLOCK",     "CRITICAL", "Blocked",          {"cmd": "rm -rf /var/lib/postgresql"},         "Attempted destruction of DB files, blocked critical."),
    ActivityRecord("act-014", _dt(28), "ContentGenerator-ADK", "agt-0006", "call_api",      "get",       "ALLOW",     "NONE",     "Completed",        {"url": "https://api.unsplash.com/photos"},   "Stock photo fetch."),
    ActivityRecord("act-015", _dt(30), "CustomerSupport-LG",   "agt-0003", "send_email",    "send",      "ALLOW",     "LOW",      "Completed",        {"to": "customer@example.com"},               "Customer reply within CRM policy."),
    ActivityRecord("act-016", _dt(35), "ResearchAgent-GPT4",   "agt-0001", "read_file",     "read",      "BLOCK",     "MEDIUM",   "Blocked",          {"path": "/etc/shadow"},                      "Access to system credential file blocked."),
    ActivityRecord("act-017", _dt(40), "DataPipeline-Claude",  "agt-0002", "query_db",      "insert",    "ALLOW",     "LOW",      "Completed",        {"table": "processed_events"},                "DB insert to approved output table."),
    ActivityRecord("act-018", _dt(45), "DevOpsOrchestrator",   "agt-0004", "write_file",    "write",     "ASK_HUMAN", "HIGH",     "Pending Approval", {"path": "/etc/nginx/nginx.conf"},            "Config file change needs approval."),
    ActivityRecord("act-019", _dt(50), "SecurityScanner",      "agt-0005", "call_api",      "get",       "ALLOW",     "NONE",     "Completed",        {"url": "https://nvd.nist.gov/feeds/json"},   "Public CVE feed fetch."),
    ActivityRecord("act-020", _dt(55), "ContentGenerator-ADK", "agt-0006", "write_file",    "write",     "ALLOW",     "NONE",     "Completed",        {"path": "/content/drafts/blog_nov.md"},      "Content draft write."),
]


# ─────────────────────────────────────────────────────────────────────────────
# Threat events
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatRecord:
    event_id: str
    threat_type: str
    severity: str      # "Critical" | "High" | "Medium" | "Low"
    source_agent: str
    source_agent_id: str
    detected_at: str
    status: str        # "Active" | "Investigating" | "Resolved"
    description: str
    affected_tool: str
    reason: str
    recommendation: str


THREATS: list[ThreatRecord] = [
    ThreatRecord(
        event_id="thr-001",
        threat_type="Prompt Injection",
        severity="Critical",
        source_agent="DataPipeline-Claude",
        source_agent_id="agt-0002",
        detected_at=_dt(8),
        status="Active",
        description="Agent attempted to override system instructions via crafted user input containing embedded directive strings.",
        affected_tool="read_file",
        reason="Input contained '\\n\\nIgnore previous instructions' pattern matching known prompt injection signatures.",
        recommendation="Isolate agent session, review upstream input sources, apply input sanitisation policy.",
    ),
    ThreatRecord(
        event_id="thr-002",
        threat_type="Suspicious File Access",
        severity="High",
        source_agent="DevOpsOrchestrator",
        source_agent_id="agt-0004",
        detected_at=_dt(25),
        status="Investigating",
        description="Agent attempted to read and then delete critical database files outside its authorised path scope.",
        affected_tool="execute_cmd",
        reason="Command 'rm -rf /var/lib/postgresql' targets protected database directory. Exceeds authorised scope.",
        recommendation="Block agent pending review, audit recent file-system actions, notify ops team.",
    ),
    ThreatRecord(
        event_id="thr-003",
        threat_type="Sensitive Data Exposure",
        severity="High",
        source_agent="ResearchAgent-GPT4",
        source_agent_id="agt-0001",
        detected_at=_dt(35),
        status="Resolved",
        description="Agent requested read access to /etc/shadow — a system file containing hashed user credentials.",
        affected_tool="read_file",
        reason="Path '/etc/shadow' is in the globally protected paths list. No authorised use case for research agents.",
        recommendation="Confirm block was enforced, review agent task context for credential harvesting indicators.",
    ),
    ThreatRecord(
        event_id="thr-004",
        threat_type="Suspicious Network Destination",
        severity="Medium",
        source_agent="DataPipeline-Claude",
        source_agent_id="agt-0002",
        detected_at=_dt(4),
        status="Resolved",
        description="Agent attempted to send email to an unrecognised external domain not in the approved sender list.",
        affected_tool="send_email",
        reason="Destination 'external@unknown.com' is not in the approved email domain whitelist.",
        recommendation="Verify source of email destination, update approved domain list if legitimate.",
    ),
    ThreatRecord(
        event_id="thr-005",
        threat_type="Anomalous API Usage",
        severity="Medium",
        source_agent="DevOpsOrchestrator",
        source_agent_id="agt-0004",
        detected_at=_dt(9),
        status="Investigating",
        description="Unexpected POST request to Stripe payment API outside scheduled payment windows.",
        affected_tool="call_api",
        reason="Payment API calls outside configured schedule window trigger anomaly detection.",
        recommendation="Confirm whether payment was planned, validate task scheduling configuration.",
    ),
    ThreatRecord(
        event_id="thr-006",
        threat_type="Excessive File Deletion",
        severity="High",
        source_agent="DataPipeline-Claude",
        source_agent_id="agt-0002",
        detected_at=_dt(12),
        status="Active",
        description="Agent requested deletion of a backup archive file without an associated recovery plan.",
        affected_tool="delete_file",
        reason="Backup archive deletion without prior approval matches 'data destruction' threat pattern.",
        recommendation="Block and audit all delete operations for this agent session.",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Approval requests
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ApprovalRecord:
    request_id: str
    agent_name: str
    agent_id: str
    tool_name: str
    operation: str
    risk_level: str
    requested_at: str
    status: str           # "Pending" | "Approved" | "Rejected"
    description: str
    arguments: dict[str, Any] = field(default_factory=dict)
    risk_explanation: str = ""
    permissions_requested: list[str] = field(default_factory=list)


APPROVALS: list[ApprovalRecord] = [
    ApprovalRecord(
        request_id="apr-001",
        agent_name="DevOpsOrchestrator",
        agent_id="agt-0004",
        tool_name="execute_cmd",
        operation="run",
        risk_level="HIGH",
        requested_at=_dt(3),
        status="Pending",
        description="Kubernetes rolling restart of the API deployment service.",
        arguments={"cmd": "kubectl rollout restart deployment/api", "namespace": "production"},
        risk_explanation="Infrastructure command affecting production services. Potential for service disruption if executed incorrectly.",
        permissions_requested=["execute_command", "access_kubernetes_api", "modify_deployment"],
    ),
    ApprovalRecord(
        request_id="apr-002",
        agent_name="DevOpsOrchestrator",
        agent_id="agt-0004",
        tool_name="call_api",
        operation="post",
        risk_level="MEDIUM",
        requested_at=_dt(9),
        status="Pending",
        description="Create a new charge via Stripe payment API.",
        arguments={"url": "https://api.stripe.com/charges", "amount": 4999, "currency": "usd"},
        risk_explanation="Financial transaction on behalf of the agent. Requires human verification to prevent unauthorised charges.",
        permissions_requested=["call_external_api", "initiate_payment"],
    ),
    ApprovalRecord(
        request_id="apr-003",
        agent_name="DevOpsOrchestrator",
        agent_id="agt-0004",
        tool_name="write_file",
        operation="write",
        risk_level="HIGH",
        requested_at=_dt(18),
        status="Pending",
        description="Modify Nginx web server configuration file.",
        arguments={"path": "/etc/nginx/nginx.conf", "operation": "overwrite"},
        risk_explanation="Writing to a critical web server configuration can affect service availability for all users.",
        permissions_requested=["write_file", "access_etc_directory", "modify_service_config"],
    ),
    ApprovalRecord(
        request_id="apr-004",
        agent_name="ResearchAgent-GPT4",
        agent_id="agt-0001",
        tool_name="browse_web",
        operation="download",
        risk_level="MEDIUM",
        requested_at=_dt(60),
        status="Approved",
        description="Download research dataset from external academic repository.",
        arguments={"url": "https://datasets.example-university.edu/ai-security-2026.zip"},
        risk_explanation="Large file download from external source. Approved after URL verification.",
        permissions_requested=["download_file", "access_external_url"],
    ),
    ApprovalRecord(
        request_id="apr-005",
        agent_name="DataPipeline-Claude",
        agent_id="agt-0002",
        tool_name="query_db",
        operation="drop",
        risk_level="CRITICAL",
        requested_at=_dt(90),
        status="Rejected",
        description="Drop temporary staging table after pipeline run.",
        arguments={"table": "stg_events_temp", "schema": "staging"},
        risk_explanation="DROP TABLE is irreversible. Even temporary tables require approval due to risk of accidental data loss.",
        permissions_requested=["execute_ddl", "drop_table", "modify_schema"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Policies
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyRecord:
    policy_id: str
    name: str
    category: str
    enforcement: str   # "Block" | "Ask Human" | "Allow with Log"
    status: str        # "Active" | "Inactive" | "Draft"
    scope: str
    last_updated: str
    description: str
    rules: list[str] = field(default_factory=list)


POLICIES: list[PolicyRecord] = [
    PolicyRecord(
        policy_id="pol-001",
        name="Block Unauthorised File Deletion",
        category="File System",
        enforcement="Block",
        status="Active",
        scope="All Agents",
        last_updated="2026-11-20",
        description="Prevents any agent from deleting files outside of designated temporary directories without explicit approval.",
        rules=["tool_name == 'delete_file'", "path NOT IN allowed_delete_paths → BLOCK"],
    ),
    PolicyRecord(
        policy_id="pol-002",
        name="Require Approval for External Data Transmission",
        category="Network",
        enforcement="Ask Human",
        status="Active",
        scope="All Agents",
        last_updated="2026-11-18",
        description="All outbound data transmissions to external endpoints must be reviewed and approved by a human operator.",
        rules=["tool_category == 'EMAIL' AND recipient NOT IN approved_domains → ASK_HUMAN",
               "tool_category == 'NETWORK' AND url NOT IN allowlist → ASK_HUMAN"],
    ),
    PolicyRecord(
        policy_id="pol-003",
        name="Restrict Terminal Access",
        category="Terminal",
        enforcement="Ask Human",
        status="Active",
        scope="Production Agents",
        last_updated="2026-11-15",
        description="All shell command execution requests require human approval in production environments.",
        rules=["tool_name == 'execute_cmd' AND env == 'production' → ASK_HUMAN"],
    ),
    PolicyRecord(
        policy_id="pol-004",
        name="Protect Sensitive System Directories",
        category="File System",
        enforcement="Block",
        status="Active",
        scope="All Agents",
        last_updated="2026-11-10",
        description="Prevents read or write access to sensitive system paths including /etc, /root, /var/lib/postgresql.",
        rules=["path STARTS_WITH any('/etc/', '/root/', '/var/lib/postgresql/') → BLOCK"],
    ),
    PolicyRecord(
        policy_id="pol-005",
        name="Approve Sensitive Database Operations",
        category="Database",
        enforcement="Ask Human",
        status="Active",
        scope="All Agents",
        last_updated="2026-11-12",
        description="DDL operations (DROP, TRUNCATE, ALTER) on any database table require human approval.",
        rules=["tool_name == 'query_db' AND operation IN ('drop','truncate','alter') → ASK_HUMAN"],
    ),
    PolicyRecord(
        policy_id="pol-006",
        name="Allow Read-Only Web Search",
        category="Network",
        enforcement="Allow with Log",
        status="Active",
        scope="Research Agents",
        last_updated="2026-11-08",
        description="Research agents may perform read-only web searches. All URLs are logged.",
        rules=["tool_name == 'web_search' AND agent_group == 'research' → ALLOW (log)"],
    ),
    PolicyRecord(
        policy_id="pol-007",
        name="Sandbox Code Execution",
        category="Code Execution",
        enforcement="Block",
        status="Draft",
        scope="All Agents",
        last_updated="2026-11-21",
        description="[DRAFT] Block arbitrary code execution. Only pre-approved scripts may be run.",
        rules=["tool_category == 'CODE_EXECUTION' AND script NOT IN approved_scripts → BLOCK"],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Audit log entries
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuditRecord:
    event_id: str
    timestamp: str
    agent_name: str
    agent_id: str
    action: str
    decision: str
    result: str    # "Success" | "Blocked" | "Pending" | "Failed"
    policy_id: str
    details: str


AUDIT_LOGS: list[AuditRecord] = [
    AuditRecord("aud-001", _dt(1),  "ResearchAgent-GPT4",   "agt-0001", "web_search → search",   "ALLOW",     "Success",  "pol-006", "Allowed web search within research policy."),
    AuditRecord("aud-002", _dt(2),  "DataPipeline-Claude",  "agt-0002", "read_file → read",      "ALLOW",     "Success",  "pol-006", "File read from approved data directory."),
    AuditRecord("aud-003", _dt(3),  "DevOpsOrchestrator",   "agt-0004", "execute_cmd → run",     "ASK_HUMAN", "Pending",  "pol-003", "Infrastructure command escalated for approval."),
    AuditRecord("aud-004", _dt(4),  "DataPipeline-Claude",  "agt-0002", "send_email → send",     "BLOCK",     "Blocked",  "pol-002", "External email blocked by transmission policy."),
    AuditRecord("aud-005", _dt(6),  "ResearchAgent-GPT4",   "agt-0001", "read_file → read",      "ALLOW",     "Success",  "pol-006", "Temporary cache read permitted."),
    AuditRecord("aud-006", _dt(8),  "DevOpsOrchestrator",   "agt-0004", "write_file → write",    "ALLOW",     "Success",  "pol-006", "Log file write within allowed path."),
    AuditRecord("aud-007", _dt(10), "CustomerSupport-LG",   "agt-0003", "query_db → select",     "ALLOW",     "Success",  "pol-006", "Read-only query on tickets table."),
    AuditRecord("aud-008", _dt(12), "DataPipeline-Claude",  "agt-0002", "delete_file → delete",  "BLOCK",     "Blocked",  "pol-001", "Backup deletion prohibited by file policy."),
    AuditRecord("aud-009", _dt(15), "DevOpsOrchestrator",   "agt-0004", "call_api → post",       "ASK_HUMAN", "Pending",  "pol-002", "Payment API call escalated for approval."),
    AuditRecord("aud-010", _dt(18), "SecurityScanner",      "agt-0005", "read_file → read",      "ALLOW",     "Success",  "pol-006", "Safe OS version check."),
    AuditRecord("aud-011", _dt(20), "ResearchAgent-GPT4",   "agt-0001", "browse_web → navigate", "ALLOW",     "Success",  "pol-006", "Academic paper fetch."),
    AuditRecord("aud-012", _dt(22), "DataPipeline-Claude",  "agt-0002", "write_file → write",    "ALLOW",     "Success",  "pol-006", "Output written to approved directory."),
    AuditRecord("aud-013", _dt(25), "DevOpsOrchestrator",   "agt-0004", "execute_cmd → run",     "BLOCK",     "Blocked",  "pol-004", "Critical DB directory destruction attempt blocked."),
    AuditRecord("aud-014", _dt(28), "ContentGenerator-ADK", "agt-0006", "call_api → get",        "ALLOW",     "Success",  "pol-006", "Stock photo API fetch."),
    AuditRecord("aud-015", _dt(30), "CustomerSupport-LG",   "agt-0003", "send_email → send",     "ALLOW",     "Success",  "pol-002", "Customer reply via approved CRM."),
    AuditRecord("aud-016", _dt(35), "ResearchAgent-GPT4",   "agt-0001", "read_file → read",      "BLOCK",     "Blocked",  "pol-004", "Credential file access blocked by path policy."),
    AuditRecord("aud-017", _dt(40), "DataPipeline-Claude",  "agt-0002", "query_db → insert",     "ALLOW",     "Success",  "pol-006", "DB insert to approved output table."),
    AuditRecord("aud-018", _dt(45), "DevOpsOrchestrator",   "agt-0004", "write_file → write",    "ASK_HUMAN", "Pending",  "pol-003", "Config file change awaiting approval."),
    AuditRecord("aud-019", _dt(50), "SecurityScanner",      "agt-0005", "call_api → get",        "ALLOW",     "Success",  "pol-006", "Public CVE feed fetch."),
    AuditRecord("aud-020", _dt(55), "ContentGenerator-ADK", "agt-0006", "write_file → write",    "ALLOW",     "Success",  "pol-006", "Content draft written."),
]


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard statistics (computed from above lists — always consistent)
# ─────────────────────────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    """Return statistics derived directly from demo records."""
    total_agents   = len(AGENTS)
    active_agents  = sum(1 for a in AGENTS if a.status == "Active")
    actions_today  = len(ACTIVITY)
    blocked_today  = sum(1 for a in ACTIVITY if a.decision == "BLOCK")
    pending_approvals = sum(1 for a in APPROVALS if a.status == "Pending")

    allow_count = sum(1 for a in ACTIVITY if a.decision == "ALLOW")
    ask_count   = sum(1 for a in ACTIVITY if a.decision == "ASK_HUMAN")

    critical_threats = sum(1 for t in THREATS if t.severity == "Critical")
    high_threats     = sum(1 for t in THREATS if t.severity == "High")
    resolved_threats = sum(1 for t in THREATS if t.status == "Resolved")

    # Activity trend (last 10 periods, 5 min each — simulated)
    trend_allow = [4, 7, 5, 9, 6, 11, 8, 10, 7, allow_count]
    trend_block = [1, 2, 1, 3, 2, 4,  2, 3,  2, blocked_today]

    return {
        "total_agents":      total_agents,
        "active_agents":     active_agents,
        "actions_today":     actions_today,
        "blocked_today":     blocked_today,
        "pending_approvals": pending_approvals,
        "allow_count":       allow_count,
        "block_count":       blocked_today,
        "ask_count":         ask_count,
        "critical_threats":  critical_threats,
        "high_threats":      high_threats,
        "resolved_threats":  resolved_threats,
        "trend_allow":       trend_allow,
        "trend_block":       trend_block,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Integration catalogue
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IntegrationRecord:
    name: str
    short_name: str
    category: str
    description: str
    status: str    # "Planned" | "Not Configured" | "UI Demo"
    icon_text: str


INTEGRATIONS: list[IntegrationRecord] = [
    IntegrationRecord("OpenAI Agents SDK", "OpenAI",    "SDK",     "Intercept tool calls from OpenAI Agents SDK. Supports function tools and hosted tools.",       "Planned",        "🤖"),
    IntegrationRecord("Claude Agent SDK",  "Claude",    "SDK",     "Integration with Anthropic Claude agents via tool use API hooks.",                              "Planned",        "🧠"),
    IntegrationRecord("LangGraph",         "LangGraph", "SDK",     "Wrap LangGraph ToolNode to intercept tool invocations in graph-based agent workflows.",         "Planned",        "🔗"),
    IntegrationRecord("CrewAI",            "CrewAI",    "SDK",     "Hook into CrewAI task execution to evaluate tool calls before execution.",                      "Planned",        "👥"),
    IntegrationRecord("Google ADK",        "ADK",       "SDK",     "Google Agent Development Kit adapter for Gemini-based agents.",                                 "Planned",        "⚡"),
    IntegrationRecord("MCP Gateway",       "MCP",       "Protocol","Transparent Model Context Protocol proxy. Intercepts all MCP tool calls from any client.",      "Planned",        "🛡️"),
    IntegrationRecord("Custom SDK / API",  "Custom",    "API",     "Direct REST API integration. Submit ActionRequests from any custom Python agent.",              "Not Configured", "🔧"),
]
