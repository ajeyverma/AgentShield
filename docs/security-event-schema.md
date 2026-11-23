# Unified Security Event Contract Schema

## 1. Schema Definition

All security events emitted in AgentShield conform to `SecurityEvent`:

| Field | Type | Description |
|---|---|---|
| `event_id` | `str` (UUID4) | Server-generated unique event identifier. |
| `event_version` | `str` | Schema version (default `"1.0"`). |
| `timestamp` | `datetime` | UTC timestamp of event creation. |
| `tenant_id` | `str` | Tenant or organization identifier. |
| `actor_id` | `str` | Initiator ID (agent, user, or system). |
| `agent_id` | `str \| None` | AI agent identifier, if applicable. |
| `integration_type` | `str \| None` | SDK or protocol channel. |
| `trace_id` | `str` | 32-character hex trace ID. |
| `span_id` | `str` | 16-character hex span ID. |
| `correlation_id` | `str` | Cross-system correlation ID. |
| `source_component` | `EventComponent` | Emitting component (gateway, engine, mcp, etc.). |
| `event_type` | `str` | Dot-separated classification string. |
| `severity` | `EventSeverity` | Severity level (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `action` | `str` | Action performed or evaluated. |
| `decision` | `str \| None` | Outcome (`ALLOW`, `BLOCK`, `ASK_HUMAN`). |
| `metadata` | `dict[str, Any]` | Scrubbed contextual details. |

---

## 2. Redaction Guarantees

Before persistence or WebSocket broadcasting, `event.sanitize_metadata()` recursively scrubs all matching patterns:
- Bearer tokens (`Bearer eyJ...`, `sk-proj-...`)
- Private API keys (`AKIA...`, `api_key=...`)
- Passwords and connection strings
- Private arguments matching sensitive keys (`password`, `secret`, `credential`, `token`, `key`)
