# AgentShield AI — Known Limitations & Threat Model Scope

Honesty and precise threat modeling are essential for runtime security systems. This document outlines the explicit boundaries, assumptions, and known limitations of AgentShield AI.

---

## 1. Architectural Boundaries

### 1.1 Non-Bypassable Execution Assumption
- **Guarantee**: AgentShield guarantees tool execution security **only** when tool execution boundaries are routed through AgentShield adapters or the Controlled Execution Gateway.
- **Limitation**: If an agent framework has native, unmonitored code execution capabilities outside the registered tool registry (e.g. unrestricted `eval()`, direct OS system calls, or unmonitored socket access), AgentShield cannot prevent execution. The host environment must enforce principle of least privilege.

### 1.2 Upstream LLM Hallucinations
- AgentShield inspects and authorizes tool calls, arguments, and responses. It does not control LLM reasoning internal weights or prevent the model from generating incorrect prose responses to the user.

---

## 2. Threat Detection Limitations

### 2.1 Heuristic & Regex Evasion
- The Prompt Injection detector uses a blend of semantic heuristics, known attack patterns, and structure analysis. Highly sophisticated novel adversarial encodings (e.g. base64 inside multi-layer rot13 steganography) may score below the critical block threshold unless combined with strict tool parameter typing policies.

### 2.2 Latency vs Deep Inspection Tradeoff
- Full deep content scanning adds $10-50\text{ms}$ per tool invocation. For multi-megabyte payloads, size caps are enforced (`AGENTSHIELD_MAX_PAYLOAD_SIZE_BYTES`) to prevent denial-of-service against the security engine.
