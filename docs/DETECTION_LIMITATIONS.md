# Threat Detection Limitations & Boundary Conditions

AgentShield AI employs deterministic, explainable security heuristics and pattern matching. Understanding the operational boundaries of this design is critical for security practitioners.

---

## 1. Prompt Injection Detection Boundaries

- **No Guaranteed 100% Detection:**
  No static or pattern-based engine can guarantee 100% detection of all possible prompt injection, adversarial semantic reframing, or jailbreak attacks.
- **Explainability vs. Obfuscation:**
  AgentShield relies on deterministic signatures, provenance tracking, and contextual signals rather than opaque LLM-based classifiers. Highly novel or multi-turn conversational injections may evade single-turn signature checks without provenance metadata.
- **Importance of Provenance:**
  Detection accuracy relies heavily on integration adapters providing accurate `ProvenanceContext`. If external untrusted text is injected into a trusted user prompt channel, detection defaults to standard textual inspection.

---

## 2. Filesystem & Network Boundaries

- **No Real File Access:**
  In Phase 5, path analysis is strictly static (`os.path.normpath`). The engine does not inspect the live host filesystem, follow symlinks, or check inode attributes.
- **DNS Rebinding & Resolution:**
  Network analysis checks URLs, IP literals, and hostname categories statically. It does not perform active DNS resolution to avoid network side-effects during authorization checks. Hostnames resolving to private IPs via DNS rebinding must be mitigated via egress firewalls or proxy resolution in future phases.
- **No Command Execution:**
  Command analysis uses static regex and AST patterns. Complex shell variable expansions (e.g., `a=rm; b=-rf; $a $b /`) are detected via obfuscation rules but cannot replace full shell emulation.
