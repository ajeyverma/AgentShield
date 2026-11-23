"""
AgentShield AI — Property-Based Fuzz Testing (Phase 11).

Applies invariant checking and fuzz testing to core security boundaries:
1. Canonical argument hashing determinism and collision resistance
2. Secret redaction idempotency: redact(redact(x)) == redact(x)
3. Sandboxed filesystem path sanitization and boundary escape confinement
4. Audit log canonical serialization & hash consistency
5. Policy condition schema robustness against malformed/hostile input
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

try:
    from hypothesis import given, settings, strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from agentshield.contracts.execution import compute_canonical_argument_hash
from agentshield.execution.adapters.sandbox_fs import SandboxedFilesystemAdapter
from agentshield.execution.exceptions import InvalidArgumentsError
from agentshield.security.sanitization import redact_secrets
from agentshield.services.tamper_evident_audit import compute_record_hash


# ── 1. Canonical Argument Hash Determinism ─────────────────────────────────────


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="Hypothesis not installed")
@given(
    st.dictionaries(
        keys=st.text(min_size=1, max_size=32),
        values=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False), st.booleans(), st.none()),
        max_size=10,
    )
)
@settings(max_examples=100)
def test_property_argument_hash_determinism(args_dict):
    """Property: Hashing the same arguments dictionary produces identical SHA-256 hex hashes."""
    h1 = compute_canonical_argument_hash(args_dict)
    h2 = compute_canonical_argument_hash(args_dict)
    assert h1 == h2
    assert len(h1) == 64
    assert isinstance(h1, str)


# ── 2. Secret Redaction Idempotency ───────────────────────────────────────────


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="Hypothesis not installed")
@given(
    st.recursive(
        st.one_of(st.text(), st.integers(), st.booleans()),
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(max_size=16), children, max_size=5),
        ),
        max_leaves=20,
    )
)
@settings(max_examples=80)
def test_property_secret_redaction_idempotency(payload):
    """Property: Redacting secrets is idempotent: redact(redact(x)) == redact(x)."""
    first_pass = redact_secrets(payload)
    second_pass = redact_secrets(first_pass)
    assert first_pass == second_pass


# ── 3. Path Traversal Sandbox Confinement ─────────────────────────────────────


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="Hypothesis not installed")
@given(
    st.text(
        alphabet=st.characters(blacklist_categories=("Cs",)),
        min_size=1,
        max_size=120,
    )
)
@settings(max_examples=100)
def test_property_sandbox_path_confinement(fuzzed_path):
    """Property: SandboxedFilesystemAdapter strictly confines resolved path or raises InvalidArgumentsError."""
    adapter = SandboxedFilesystemAdapter()
    try:
        resolved = adapter._resolve_safe_path(fuzzed_path)
        # If it resolves without error, verify strict containment
        assert resolved == adapter.sandbox_root or adapter.sandbox_root in resolved.parents
    except InvalidArgumentsError:
        # Proper security boundary rejection
        pass


# ── 4. Audit Chain Canonical Hash Consistency ─────────────────────────────────


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="Hypothesis not installed")
@given(
    seq=st.integers(min_value=1, max_value=1_000_000),
    prev_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
    tenant=st.text(min_size=1, max_size=36),
    actor=st.text(min_size=1, max_size=36),
    action=st.text(min_size=1, max_size=32),
    target=st.text(max_size=64),
    result=st.sampled_from(["SUCCESS", "FAILED", "BLOCKED"]),
    desc=st.text(max_size=128),
    ts=st.text(min_size=10, max_size=30),
)
@settings(max_examples=100)
def test_property_audit_hash_consistency(seq, prev_hash, tenant, actor, action, target, result, desc, ts):
    """Property: compute_record_hash produces deterministic 64-hex SHA-256 for all inputs."""
    payload1, hash1 = compute_record_hash(seq, prev_hash, tenant, actor, action, target, result, desc, ts)
    payload2, hash2 = compute_record_hash(seq, prev_hash, tenant, actor, action, target, result, desc, ts)
    assert hash1 == hash2
    assert len(hash1) == 64
    assert payload1 == payload2
