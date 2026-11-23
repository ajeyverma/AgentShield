# Behavioral Anomaly Detection

The **Behavioral Anomaly Detector** (`DET-BEH-006`) applies explainable statistical and heuristic evaluation over historical `ActivityEvent` records.

---

## 1. Analysis Dimensions

1. **Request Rate Burst Detection:**
   - Evaluates the rolling 60-second window of actions for an agent.
   - If an agent generates more than 30 actions within 60 seconds (`MAX_REQUESTS_PER_MINUTE`), an anomaly finding is created to catch runaway automation loops or enumeration attacks.
2. **Repeated Security Denials:**
   - Detects when an agent encounters 3 or more consecutive `BLOCK` authorization decisions (`MAX_CONSECUTIVE_DENIALS`).
   - Flags policy compliance issues and potential brute-force boundary testing.
3. **High-Risk Action Sequences:**
   - Identifies suspicious operational transitions (e.g. `read_file` immediately followed by `http_post` or network egress).
   - Flags potential data exfiltration chains.

---

## 2. Tenant & Agent Isolation

- Behavioral history is filtered strictly by `(user_id, agent_id)`.
- Activity from one user or agent never affects the baseline or score of another.
- **Graceful Baseline Handling:** New agents without historical records generate zero false positives.
