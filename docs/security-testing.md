# Security Testing Framework & Invariant Verification

## 1. Overview

AgentShield provides a multi-tiered security testing strategy:
1. **Security Regression Tests** (`tests/security_testing/`): Deterministic regression verification of security engine invariants, RBAC boundaries, and cryptographic chain validity.
2. **Property-Based Fuzz Testing** (`tests/fuzzing/`): Automated fuzzing with Hypothesis to verify schema resilience and boundary containment.
3. **Safe Red-Team Simulation Harness** (`tests/red_team/`): 12 synthetic attack scenarios testing defensive depth.
4. **Performance & Latency Benchmarks** (`tests/benchmarks/`): Automated SLA latency and throughput verification.

---

## 2. Tested Security Invariants

- **Invariant 1**: An action evaluated as `BLOCK` NEVER executes the underlying tool adapter.
- **Invariant 2**: An action evaluated as `ASK_HUMAN` NEVER executes the tool adapter prior to authorized human approval.
- **Invariant 3**: A mandatory `BLOCK` decision cannot be overridden or approved by any human role.
- **Invariant 4**: An approval token cannot be replayed or used more than once.
- **Invariant 5**: Tampering with argument payloads for an approved execution is strictly rejected by argument hash verification.
- **Invariant 6**: AI agents are strictly forbidden from approving requests (zero self-approval).
- **Invariant 7**: Any modification, deletion, or reordering of audit records immediately breaks hash chain verification.
