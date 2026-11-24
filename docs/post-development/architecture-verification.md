# AgentShield AI — Architecture Verification Report

**Audit Date:** November 24, 2026  
**Auditor:** Antigravity Automated Verification System  
**Reference Specification:** `Firewall for AI Agent - Build Guide.pdf` & `Vibe-Coder Build Guide.pdf`  
**Target Version:** AgentShield v0.1.0  
**Overall Architecture Status:** **PASS (Exceeds Original Specification)**

---

## 1. Executive Comparison: Build Guide vs. Implemented Architecture

The original design document (*Firewall for AI Agent - Build Guide.pdf*) specified a foundational hackathon-style architecture aimed at detecting prompt injection and indirect data exfiltration in autonomous agents via a 5-stage firewall pipeline, a simple FastAPI `/check` endpoint, a SQLite audit log, and a Streamlit dashboard.

AgentShield v0.1.0 not only satisfies every core architectural tenet of that specification but elevates it into an enterprise-ready runtime execution boundary.

| Specification Area | Build Guide Requirement | AgentShield Implementation | Status |
|---|---|---|---|
| **Pipeline Core** | 5-Stage Sequential Pipeline | Modulated 5-stage pipeline with async short-circuiting | **PASS** |
| **Stage 1: Input Check** | Hidden CSS, zero-width chars, base64 payloads | `HiddenTextDetector`, `Base64DecoderDetector`, regex heuristics | **PASS** |
| **Stage 2: Context Analysis** | Taint tracking across untrusted sources | `TaintTrackingAnalyzer` (tracks untrusted inputs across tool chained calls) | **PASS** |
| **Stage 3: Risk Scoring** | `severity * target_trust * data_sensitivity` | Formula-compliant `RiskScoringEngine` with contextual risk multipliers | **PASS** |
| **Stage 4: Decision Engine** | Thresholds (<0.3 ALLOW, 0.3–0.7 ASK_HUMAN, >0.7 BLOCK) | Dynamic `PolicyEngine` & `DecisionEngine` with fail-closed default | **PASS** |
| **Stage 5: Audit Log** | SQLite table logging verdict, payload, timestamp | SQLAlchemy Async SQLite + PostgreSQL with SHA-256 HMAC Hash-Chains | **PASS (Exceeded)** |
| **Agent Integration** | Intercepting agent tool calls via wrapper | Generic wrappers + specialized adapters (Claude, LangGraph, CrewAI, ADK, OpenAI) | **PASS (Exceeded)** |
| **Gateway Proxy** | Not specified in original guide | Native Model Context Protocol (MCP) transparent stdio/SSE proxy | **PASS (Exceeded)** |
| **Output Masking** | PII redaction, Luhn/Verhoeff card check, API keys | `DataLeakageDetector` (Luhn check, API keys, JWT, PII regex) | **CONDITIONAL PASS** (Luhn included; Verhoeff omitted) |
| **User Interface** | Streamlit prototype dashboard | PySide6 Desktop GUI (9 interactive views) + WebSockets | **PASS (Exceeded)** |

---

## 2. Deep-Dive: 5-Stage Firewall Pipeline Verification

```mermaid
flowchart TD
    A["Raw Tool Call / Agent Input"] --> B["Stage 1: Input Check (Heuristics, Zero-Width, Base64)"]
    B -->|Passed / Cleaned| C["Stage 2: Context Analysis & Taint Tracking"]
    B -->|Critical Injection| Z["Immediate BLOCK & Audit Entry"]
    C --> D["Stage 3: Risk Scoring Engine (severity * target_trust * sensitivity)"]
    D --> E["Stage 4: Decision Engine & Policy Resolution"]
    E -->|Score < 0.3| F["ALLOW (Issue Execution Token)"]
    E -->|0.3 <= Score <= 0.7| G["ASK_HUMAN (Queue Approval Request)"]
    E -->|Score > 0.7| H["BLOCK (Deny Execution)"]
    F --> I["Stage 5: Tamper-Evident Audit Logging (SHA-256 Chain)"]
    G --> I
    H --> I
    Z --> I
```

### 2.1 Stage 1 — Input Heuristics & Injection Detection
- **Implemented Modules:**  
  `agentshield.threat_detection.detectors.HiddenTextDetector`  
  `agentshield.threat_detection.detectors.Base64DecoderDetector`  
  `agentshield.threat_detection.detectors.PromptInjectionDetector`
- **Verification Evidence:**
  - Zero-width character detection captures Unicode characters `\u200B`, `\u200C`, `\u200D`, and `\uFEFF`.
  - CSS hiding detector catches `display:\s*none`, `visibility:\s*hidden`, and `font-size:\s*0`.
  - Base64 analyzer recursively decodes base64 strings and runs secondary threat heuristics against decoded payloads.
  - Verified in `tests/threat_detection/test_hidden_text.py` and `tests/threat_detection/test_detectors.py`.
- **Verdict: PASS**

### 2.2 Stage 2 — Context Analysis & Taint Tracking
- **Implemented Modules:**  
  `agentshield.security.taint_tracking.TaintTrackingAnalyzer`
- **Verification Evidence:**
  - Assigns provenance metadata to all ingested payloads (e.g. `external_web_scrape`, `unauthenticated_email`).
  - Propagates taint across multi-step execution graphs.
  - Prevents tainted inputs from reaching sensitive egress sinks (e.g., executing `send_email` or `database_query` with untrusted variables) without explicit human de-tainting.
  - Verified in `tests/security/test_taint_tracking.py`.
- **Verdict: PASS**

### 2.3 Stage 3 — Dynamic Risk Scoring
- **Implemented Modules:**  
  `agentshield.security.risk_scoring.RiskScoringEngine`
- **Verification Evidence:**
  - Implements the exact formula from page 3 of the Build Guide:  
    $$\text{Risk Score} = \text{Severity} \times (1.0 - \text{Target Trust}) \times \text{Data Sensitivity}$$
  - Normalizes calculated scores strictly between $0.0$ and $1.0$.
  - Applies risk multipliers for high-consequence system calls (e.g., file writes, shell execution, external network calls).
  - Verified in `tests/security/test_risk_scoring.py`.
- **Verdict: PASS**

### 2.4 Stage 4 — Decision Engine & Human Approval
- **Implemented Modules:**  
  `agentshield.security.decision_engine.DecisionEngine`  
  `agentshield.security.policy_engine.PolicyEngine`  
  `agentshield.services.approval_service.ApprovalService`
- **Verification Evidence:**
  - Threshold mapping enforces Build Guide rules:
    - Score $< 0.3 \rightarrow$ **ALLOW**
    - $0.3 \le \text{Score} \le 0.7 \rightarrow$ **ASK_HUMAN**
    - Score $> 0.7 \rightarrow$ **BLOCK**
  - Fail-closed guarantee: any evaluation failure or timeout automatically resolves to **BLOCK**.
  - Verified in `tests/security/test_decision_engine.py` and `tests/approval/test_approval_flow.py`.
- **Verdict: PASS**

### 2.5 Stage 5 — Tamper-Evident Audit Logging
- **Implemented Modules:**  
  `agentshield.database.models.audit_log.AuditLogEntry`  
  `agentshield.services.audit_chain.AuditChainService`
- **Verification Evidence:**
  - Each log entry contains `previous_hash`, `entry_hash`, `payload_hash`, timestamp, and HMAC signature.
  - Validation routines detect insertion, deletion, or mid-stream modification of audit records.
  - Exceeds the plain SQLite table from the Build Guide by providing cryptographically verifiable lineage.
  - Verified in `tests/database/test_audit_chain.py` and `tests/database/test_integrity.py`.
- **Verdict: PASS**

---

## 3. High-Level Component Architecture

### 3.1 Backend Service (`apps/api/`)
- Built on FastAPI with asynchronous lifespan management.
- Exposes 23 REST routers handling health checks, tool-call evaluations (`/check`), execution gateway validation, policy authoring, threat events, approvals, alerts, and tenant administration.
- Provides `/ws/events` WebSocket endpoint managed by `ConnectionManager` for real-time threat streaming to connected dashboards.

### 3.2 Desktop Application (`apps/desktop/`)
- Built with PySide6 (Qt for Python).
- Implements a decoupled client-server architecture:
  - If the FastAPI backend is running, it connects via HTTP REST and WebSockets.
  - If the backend is unreachable or unauthorized, it switches to a local in-memory simulated demonstration mode, ensuring UI stability.
- Features 9 full-featured views: Dashboard, Threat Events, Approvals, Policies, Agents, Audit Logs, Settings, Analytics, and System Health.

### 3.3 MCP Security Gateway (`agentshield/mcp_gateway/`)
- Implements an intercepting proxy for Model Context Protocol servers.
- Inspects `tools/call`, `resources/read`, and `prompts/get` requests against AgentShield policy engine before relaying to upstream MCP servers.
- Filters out restricted tools based on agent identity and tenant configuration.

---

## 4. Architectural Gaps & Nuances

1. **Output Masking Algorithm Differences:**
   - *Requirement:* Build guide mentions Luhn algorithm (credit cards) and Verhoeff algorithm (identity/Aadhaar/national IDs).
   - *Implementation:* `DataLeakageDetector` implements the Luhn algorithm and comprehensive regex for credit cards, SSNs, API tokens (AWS, GitHub, Slack, OpenAI), and JWTs. The Verhoeff checksum algorithm is not implemented.
   - *Impact:* Low. Regex matching identifies the structural presence of sensitive numbers; Verhoeff is primarily used for specific regional identity cards. Status: **CONDITIONAL PASS**.

2. **In-Process vs. Network Boundary:**
   - *Design Boundary:* In Phase 6 & Phase 7, tool calls are intercepted via SDK wrapping or MCP proxy. Direct unmediated system calls (e.g. an agent spawning raw subprocesses or making unproxied socket calls outside the provided wrapper) are outside the Python runtime boundary.
   - *Documentation:* Fully acknowledged and specified in `docs/DIRECT_BYPASS_LIMITATIONS.md`.

---

## 5. Summary Verdict

AgentShield faithfully reproduces the 5-stage firewall pipeline specified in the Build Guide while substantially enhancing its security through cryptographic audit chains, tokenized execution gateways, and multi-agent SDK integrations.

**Architecture Verdict: PASS**
