# Observability, Distributed Tracing & Metrics

## 1. Distributed Tracing Primitives

AgentShield tracks every tool execution, security evaluation, and authorization transition using lightweight, zero-dependency async contextvars.

### 1.1 Trace Identifiers
- **Trace ID**: 32-character hexadecimal string representing the root transaction.
- **Span ID**: 16-character hexadecimal string representing a specific component boundary.
- **Correlation ID**: Cross-system correlation token maintained across SDK adapters and gateway requests.

```python
with trace_span("gateway.execute_request", resource="sandbox_fs:read_file") as span:
    # Sub-operations automatically inherit parent_span_id
    decision = security_engine.evaluate_action(...)
```

---

## 2. Structured JSON Logging

All logs in AgentShield use `StructuredJsonFormatter`:
- Timestamps in ISO-8601 UTC.
- Automatic correlation with active `trace_id`, `span_id`, and `correlation_id`.
- Automatic recursive secret masking replacing credentials, tokens, and keys with `[REDACTED]`.

---

## 3. Metrics Engine

The `SecurityMetricsCollector` provides lock-free, thread-safe metrics collection:

### 3.1 Security Counters
- `security.decisions.ALLOW`
- `security.decisions.BLOCK`
- `security.decisions.ASK_HUMAN`
- `security.requests.total`
- `security.threats.detected`
- `security.approvals.granted`
- `security.approvals.rejected`

### 3.2 Operational Percentiles
Sliding window of the last 1,000 latencies:
- **p50 (Median)**: Target < 10ms (Observed: 0.08ms – 1.41ms)
- **p95**: Target < 25ms (Observed: 0.15ms – 2.44ms)
- **p99**: Target < 50ms (Observed: 0.45ms – 3.10ms)
