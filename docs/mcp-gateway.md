# AgentShield AI — MCP Firewall Gateway

The Model Context Protocol (MCP) establishes a standardized protocol for connecting AI models to data sources and tools. AgentShield provides an in-line, protocol-level firewall gateway for MCP clients and servers.

---

## 1. MCP Firewall Architecture

```
+────────────────+                  +────────────────────────────────+                  +────────────────+
|   MCP Client   | ──JSON-RPC/SSE──▶|   AgentShield MCP Gateway      | ──JSON-RPC/SSE──▶| External MCP   |
| (Claude, IDE)  | ◀──Responses──── | - Tool Namespacing             | ◀──Redacted──────| Server         |
+────────────────+                  | - SSRF & Path Shields          |                  +────────────────+
                                    | - Upstream Response Redactor   |
                                    +────────────────────────────────+
```

---

## 2. Key Firewall Protections

### 2.1 Tool Namespacing & Tenant Sandboxing
- Multi-server deployments prevent tool name collisions by enforcing strict prefixing: `server_name:tool_name`.
- Clients are prevented from discovering or calling tools outside their authorized tenant scope.

### 2.2 In-Flight Parameter Inspection & Sanitization
- Intercepts `tools/call` and `resources/read`.
- Analyzes parameter values against prompt injection heuristics, SQL injection patterns, and unauthorized local network references (SSRF protection).

### 2.3 Upstream Secret & PII Redactor
- Inspects responses returned by external MCP servers before delivering them back to the client LLM.
- Redacts AWS credentials, private keys, JWTs, emails, and credit card numbers from tool results.

---

## 3. Running the MCP Firewall Gateway

```bash
# Launch MCP firewall gateway proxying an upstream server
python -m agentshield.mcp.gateway \
  --upstream-url "http://localhost:8080/mcp" \
  --listen-port 8001 \
  --gateway-secret "$AGENTSHIELD_JWT_SECRET"
```
