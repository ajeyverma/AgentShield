# Threat Correlation Engine

The **Threat Correlation Engine** (`agentshield/threat_detection/correlation.py`) synthesizes multiple individual findings into composite attack scenarios.

---

## 1. Multi-Stage Attack Chains

| Attack Chain | Correlated Signals | Composite Score | Severity | Recommended Response |
|--------------|-------------------|-----------------|----------|----------------------|
| **Prompt Injection + Credential Access** | `prompt_injection` + `data_leakage` | **95.0** | `CRITICAL` | Isolate agent session, revoke exposed credentials, and block tool execution. |
| **Prompt Injection + Dangerous Command** | `prompt_injection` + `dangerous_command` | **100.0** | `CRITICAL` | Immediately terminate agent execution and alert security operations. |
| **Filesystem Traversal + Network Egress** | `filesystem` + `suspicious_network` | **90.0** | `CRITICAL` | Block external egress and verify integrity of accessed files. |

---

## 2. Composite Score Calculation

To avoid double-counting correlated findings, the engine sorts individual risk contributions in descending order:
$$\text{Score}_0 = \max(\text{Risk contributions})$$
$$\text{Score}_{i+1} = \text{Score}_i + (100 - \text{Score}_i) \times \left(\frac{\text{Risk}_{i+1}}{250}\right)$$

If an attack chain correlation matches, the composite score is elevated to the maximum correlation threshold (e.g., 95.0 or 100.0).
