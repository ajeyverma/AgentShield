# AgentShield AI — Risk Scoring Methodology

## Overview

AgentShield calculates an explainable, deterministic risk score on a scale from `0.0` to `100.0` for every action request.

---

## Qualitative Risk Classifications

| Risk Level | Score Range | Default Behavior |
|------------|-------------|------------------|
| `LOW` | 0.0 – 24.9 | Permitted if authorized by permissions |
| `MEDIUM` | 25.0 – 49.9 | Standard monitoring |
| `HIGH` | 50.0 – 74.9 | Elevated scrutiny; requires approval if threshold exceeded |
| `CRITICAL` | 75.0 – 100.0 | Immediate block or mandatory human approval |

---

## Evaluated Risk Factors

1. **Tool Category Sensitivity:**
   - Arbitrary Terminal / Code Execution: `+40.0`
   - Unknown Tool Category: `+35.0`
   - Database Access: `+30.0`
   - External Network / HTTP: `+25.0`
   - Filesystem: `+20.0`
   - Browser: `+15.0`

2. **Operation Destructiveness:**
   - Destructive operations (`delete`, `drop`, `truncate`, `kill`): `+35.0`
   - State-modifying operations (`write`, `insert`, `update`, `send`): `+15.0`
   - Read-only operations (`read`, `list`, `get`): `+0.0`

3. **Target Resource Sensitivity:**
   - System files, credentials, private keys, `.env`, credentials: `+30.0`
   - Missing resource context on state-modifying action: `+15.0`

4. **Elevated Requested Scopes:**
   - Requests for `admin`, `root`, `write`, `execute`: `+10.0` to `+20.0`
