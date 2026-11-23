# AgentShield AI — Policy Evaluation Engine

## Overview

The Policy Evaluation Engine combines built-in specialized domain rules with dynamic, structured user-defined database policies.

---

## 1. Built-in Domain Security Rules

| Rule ID | Name | Target Category | Default Outcome | Trigger Conditions |
|---------|------|-----------------|-----------------|-------------------|
| `FS-001` | Sensitive Path Guard | `FILE_SYSTEM` | `BLOCK` | Path traversal (`..`), `/etc/passwd`, `/etc/shadow`, `.env`, `.ssh/id_rsa`, `SAM`, `SYSTEM` |
| `FS-002` | Destructive File Operations | `FILE_SYSTEM` | `ASK_HUMAN` | File deletion, removal, unlinking, directory deletion |
| `NET-001` | Cloud Metadata & SSRF Guard | `NETWORK` | `BLOCK` | Access to `169.254.169.254`, `metadata.google.internal`, loopback probing (`127.0.0.1`), suspicious ports (`4444`, `1337`) |
| `TERM-001` | Shell & Command Guard | `TERMINAL` | `BLOCK` / `ASK_HUMAN` | Catastrophic commands (`rm -rf /`, fork bombs, `dd`) are `BLOCK`ed; generic shell execution requires `ASK_HUMAN` |
| `DB-001` | Database Modification Guard | `DATABASE` | `ASK_HUMAN` | `DROP TABLE`, `TRUNCATE`, unbounded `DELETE FROM` |

---

## 2. Dynamic User Policies

User policies are stored in the database (`policies` table) and loaded per authenticated user.

### Structured Policy Schema (JSON)
No arbitrary Python code or shell scripts are ever evaluated:
```json
{
  "tools": ["curl*", "http_fetch"],
  "operations": ["post", "upload"],
  "resources": ["https://unapproved.external.api/*"],
  "outcome": "BLOCK",
  "reason": "Outbound data transmission to unapproved external endpoints is prohibited."
}
```

### Enforcement Modes
- **`enforce`:** Active enforcement; triggered outcome (`BLOCK`, `ASK_HUMAN`) is enforced.
- **`monitor`:** Passive auditing; matches are recorded in decision reasons without blocking.
- **`disabled`:** Ignored during evaluation.
