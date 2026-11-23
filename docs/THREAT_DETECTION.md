# Threat Detection Engine Architecture

The **AgentShield AI Threat Detection Engine** (Phase 5) operates as a modular, explainable, and deterministic security analysis system. It inspects incoming AI agent action requests, their source provenance, and surrounding historical context to identify potentially malicious or anomalous activities.

---

## 1. Core Principles

1. **Detection is NOT Authorization:**
   - The Threat Detection Engine identifies suspicious behavior, anomalies, and potential attacks.
   - It **never** issues final authorization decisions (`ALLOW` / `BLOCK` / `ASK_HUMAN`).
   - The Phase 4 Security Decision Engine remains the sole authority for security authorization.
2. **Never Fail Open:**
   - If an individual detector fails or encounters an error, the coordinator records an `incomplete_analysis` status with error details.
   - For high-privilege or sensitive actions, an incomplete analysis is treated as a risk factor under fail-closed policies.
3. **No Direct Tool Execution:**
   - Detectors perform static analysis and metadata inspection only.
   - Commands are never executed, files are never modified, and arbitrary remote endpoints are never contacted to test destinations.
4. **Complete Secret Redaction:**
   - Cleartext credentials, API keys, and sensitive tokens are strictly redacted before evidence is persisted or broadcast.

---

## 2. Detection Flow

```
+-------------------------------------------------------------+
|             Incoming ActionRequest + Provenance              |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|               ThreatDetectionCoordinator                    |
|   - Isolates execution per detector with timers             |
|   - Captures exceptions safely (fail-closed flagging)        |
+-------------------------------------------------------------+
                               |
   +-------------+-------------+-------------+-------------+
   |             |             |             |             |
   v             v             v             v             v
+----------+ +----------+ +----------+ +----------+ +----------+
|  Prompt  | |   Data   | |Filesystem| | Command  | | Network  |
|Injection | | Leakage  | | Threats  | | Analysis | | Threats  |
| (PI-001) | |(DATA-002)| | (FS-003) | |(CMD-004) | |(NET-005) |
+----------+ +----------+ +----------+ +----------+ +----------+
                               |
                               v
+-------------------------------------------------------------+
|                 Behavioral Anomaly Detector                 |
|             (Tenant-isolated historical context)            |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                  ThreatCorrelationEngine                    |
|  - Identifies multi-stage attack chains                      |
|  - Calculates composite threat score (0-100)                |
|  - Determines highest severity (LOW/MED/HIGH/CRITICAL)      |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                   ThreatAnalysisResult                      |
|  -> Ingested as a supplementary signal by Phase 4 Evaluator |
+-------------------------------------------------------------+
```

---

## 3. Registered Detectors

| Detector ID | Name | Category | Version | Primary Targets |
|-------------|------|----------|---------|-----------------|
| `DET-PI-001` | Prompt Injection Detector | `prompt_injection` | 1.0.0 | Instruction overrides, jailbreaks, system disclosure, role forgery |
| `DET-DATA-002` | Sensitive Data Leakage Detector | `data_leakage` | 1.0.0 | Cleartext API keys, tokens, passwords, private keys, outbound egress |
| `DET-FS-003` | Filesystem Threat Detector | `filesystem` | 1.0.0 | Path traversal, restricted OS system folders, destructive file deletion |
| `DET-CMD-004` | Command Analysis Detector | `dangerous_command` | 1.0.0 | Catastrophic commands, reverse shells, privilege escalation, evasion |
| `DET-NET-005` | Network Threat Detector | `suspicious_network` | 1.0.0 | Cloud metadata SSRF, loopback access, suspicious ports, dangerous schemes |
| `DET-BEH-006` | Behavioral Anomaly Detector | `behavioral_anomaly` | 1.0.0 | Request rate spikes, repeated blocks, read->network egress sequences |
