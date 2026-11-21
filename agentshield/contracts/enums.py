"""
AgentShield AI — Shared Enumerations.

All enums used across contracts, the security core, the backend, and
the desktop application are defined here.  Using a single canonical
location prevents duplication and ensures the same vocabulary is used
in every integration path (SDK/API and MCP).
"""

from enum import Enum


# ---------------------------------------------------------------------------
# Security Decision
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    """The three possible outcomes of a security evaluation.

    ALLOW     — The action is authorized and safe; forward it to the tool.
    BLOCK     — The action is unauthorized or dangerous; reject it immediately.
    ASK_HUMAN — The action is ambiguous; pause execution and request human
                approval before proceeding.

    Design note: clients that submit action requests MUST NOT be trusted to
    supply or override the decision value.  The decision is always produced
    by the AgentShield backend security core.
    """

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ASK_HUMAN = "ASK_HUMAN"


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Qualitative risk classification assigned by the risk engine.

    NONE     — No meaningful risk detected.
    LOW      — Minor risk; likely safe with standard controls.
    MEDIUM   — Moderate risk; warrants additional scrutiny.
    HIGH     — Significant risk; likely requires human review or blocking.
    CRITICAL — Severe risk; should be blocked or escalated immediately.
    """

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Integration type
# ---------------------------------------------------------------------------


class IntegrationType(str, Enum):
    """Identifies the integration channel through which an action arrived.

    SDK_OPENAI  — OpenAI Agents SDK adapter.
    SDK_CLAUDE  — Anthropic Claude agent adapter.
    SDK_LANGGRAPH — LangGraph adapter.
    SDK_CREWAI  — CrewAI adapter.
    SDK_GOOGLE_ADK — Google Agent Development Kit adapter.
    SDK_CUSTOM  — Custom Python agent using the AgentShield SDK directly.
    MCP         — Model Context Protocol proxy (any MCP-compatible client).
    API         — Direct REST API call (e.g. from a service or script).
    UNKNOWN     — Integration type could not be determined; treat with care.
    """

    SDK_OPENAI = "SDK_OPENAI"
    SDK_CLAUDE = "SDK_CLAUDE"
    SDK_LANGGRAPH = "SDK_LANGGRAPH"
    SDK_CREWAI = "SDK_CREWAI"
    SDK_GOOGLE_ADK = "SDK_GOOGLE_ADK"
    SDK_CUSTOM = "SDK_CUSTOM"
    MCP = "MCP"
    API = "API"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Tool / action categorization
# ---------------------------------------------------------------------------


class ToolCategory(str, Enum):
    """High-level category of the tool being invoked.

    Used by the policy engine to apply category-level rules without
    requiring a specific rule per named tool.
    """

    FILE_SYSTEM = "FILE_SYSTEM"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"
    EMAIL = "EMAIL"
    BROWSER = "BROWSER"
    TERMINAL = "TERMINAL"
    EXTERNAL_API = "EXTERNAL_API"
    MEMORY = "MEMORY"
    CODE_EXECUTION = "CODE_EXECUTION"
    AUTHENTICATION = "AUTHENTICATION"
    MESSAGING = "MESSAGING"
    CALENDAR = "CALENDAR"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Action / request lifecycle status
# ---------------------------------------------------------------------------


class ActionStatus(str, Enum):
    """Lifecycle state of an action request within AgentShield.

    PENDING    — Received and queued for evaluation.
    EVALUATING — The security core is currently assessing the request.
    APPROVED   — Approved by the security core (ALLOW decision).
    BLOCKED    — Rejected by the security core (BLOCK decision).
    AWAITING_APPROVAL — Forwarded to a human approver (ASK_HUMAN decision).
    EXECUTING  — Authorized action is being forwarded to the target tool.
    COMPLETED  — Tool execution finished successfully.
    FAILED     — Tool execution encountered an error after authorization.
    EXPIRED    — Human approval was not received within the timeout window.
    CANCELLED  — Action was cancelled by the agent or the approver.
    """

    PENDING = "PENDING"
    EVALUATING = "EVALUATING"
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


# ---------------------------------------------------------------------------
# Approval status (subset of lifecycle, human-approval specific)
# ---------------------------------------------------------------------------


class ApprovalStatus(str, Enum):
    """Status of a human approval request.

    PENDING  — Waiting for a human decision.
    APPROVED — Human approved the action.
    REJECTED — Human rejected the action.
    EXPIRED  — The approval window elapsed without a response.
    """

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


# ---------------------------------------------------------------------------
# Deployment / environment
# ---------------------------------------------------------------------------


class DeploymentMode(str, Enum):
    """Deployment mode for the AgentShield platform.

    LOCAL  — Backend and desktop on the same machine or LAN.
             SQLite is acceptable for development.
    REMOTE — Backend on a remote server; desktop connects via HTTPS.
             PostgreSQL is required.
    """

    LOCAL = "LOCAL"
    REMOTE = "REMOTE"
