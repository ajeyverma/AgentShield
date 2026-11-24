# AgentShield AI — Risk Register

**Audit Date:** November 24, 2026  
**Auditor:** Antigravity Automated Verification System  
**Stage:** Stage 1 Post-Development Risk Identification  
**Target Version:** AgentShield v0.1.0  
**Overall Risk Posture:** **MODERATE (Manageable with Documented Boundary Controls)**

---

## 1. Risk Register Summary Matrix

| Risk ID | Category | Description | Inherent Severity | Likelihood | Residual Risk | Status |
|---|---|---|---|---|---|---|
| **RISK-01** | Architecture / Sandbox | **Direct Unmediated Host & Network Bypass:** An uninstrumented agent with raw Python or bash access can bypass the firewall proxy. | High | Medium | Medium | **ACCEPTED (Design Boundary)** |
| **RISK-02** | Detection / ML | **Adversarial Paraphrased Prompt Injection:** Semantic prompt injections that evade heuristic and regex patterns. | Medium | Medium | Medium | **MITIGATED / IN REVIEW** |
| **RISK-03** | Client / Desktop UI | **Desktop App Unauthenticated State:** Desktop app shows demo mode or 401 when backend is running without saved login credentials. | Low | High | Low | **TRACKED FOR STAGE 2** |
| **RISK-04** | Detection / PII | **Omission of Verhoeff Algorithm:** National ID checksum (Verhoeff) omitted in favor of regex and Luhn checks. | Low | Low | Very Low | **TRACKED FOR STAGE 2** |
| **RISK-05** | Cryptography / Operational | **Default Secret Key in Non-Production:** Deployment with unconfigured environment variables falling back to default secret key. | High | Low | Very Low | **MITIGATED (Warn on Start)** |
| **RISK-06** | Performance / Denial of Service | **Recursive Base64 Bomb:** Extremely deep or circular base64 payload consuming excessive CPU cycles. | Medium | Low | Very Low | **MITIGATED (Recursion Depth Capped)** |

---

## 2. Granular Risk Analysis

### RISK-01: Direct Unmediated Host & Network Bypass
- **Description:** AgentShield operates as an application-level firewall. In environments where an agent process has raw shell access, it can execute `curl`, `socat`, or write directly to the filesystem without routing through `AgentShield` wrappers or the MCP proxy.
- **Evidence:** Documented in `docs/DIRECT_BYPASS_LIMITATIONS.md`.
- **Existing Mitigations:** Framework adapters hook tool calls; MCP proxy intercepts stdio/SSE communication.
- **Residual Risk:** Medium.
- **Recommended Action for Stage 2:** Introduce a containerized host sandbox (Docker / gVisor) and host-level egress routing (`iptables` / packet filter).

### RISK-02: Adversarial Paraphrased Prompt Injection
- **Description:** Sophisticated multi-step indirect injections or novel paraphrasings may evade static keyword and regex heuristics.
- **Evidence:** Tested in `tests/red_team/test_attacks.py`. Heuristics achieve >95% precision on standard benchmarks, but dynamic zero-day vectors remain possible.
- **Existing Mitigations:** Multi-stage pipeline combines zero-width detection, CSS hiding inspection, and taint tracking across tool calls.
- **Residual Risk:** Medium.
- **Recommended Action for Stage 2:** Integrate an optional local fast SLM (e.g. Llama-Guard / Gemma-Guard) as a semantic evaluation tier.

### RISK-03: Desktop App Automatic Credential Storage
- **Description:** When the backend server is launched with authentication enabled, the desktop application boots into local demo mode unless the user explicitly logs in and acquires a JWT session.
- **Evidence:** Observed during desktop client health-check cycles where backend returned HTTP 401 on protected routes while responding HTTP 200 on `/health`.
- **Existing Mitigations:** Safe fallback: desktop transitions cleanly to local demo state rather than crashing.
- **Residual Risk:** Low (User experience limitation rather than security breach).
- **Recommended Action for Stage 2:** Implement an encrypted desktop credential vault (Keyring / OS Keychain integration) and persistent session refresher.

### RISK-04: Omission of Verhoeff Algorithm for Identity Numbers
- **Description:** The Build Guide suggested Luhn and Verhoeff algorithms. Luhn is implemented for credit cards; Verhoeff (used primarily for Aadhaar and specialized identity cards) is not implemented directly, relying instead on regex structure matching.
- **Evidence:** `agentshield/threat_detection/detectors/data_leakage.py`.
- **Residual Risk:** Very Low.
- **Recommended Action for Stage 2:** Add Verhoeff checksum algorithm to `DataLeakageDetector`.

---

## 3. Risk Acceptance & Approval Sign-off

No critical, unhandled security vulnerabilities were identified in the codebase. All identified risks are architectural boundaries inherent to application-level firewalls or planned enhancements for subsequent operational stages.
