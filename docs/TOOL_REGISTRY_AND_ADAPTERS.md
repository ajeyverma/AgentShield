# Controlled Tool Registry & Adapters Specification

## 1. Controlled Tool Registry

The `ToolRegistry` (`agentshield.execution.registry.tool_registry`) maintains the authoritative catalogue of server-side tools available to AI agents. It performs strict structural and schema validation before any execution request reaches the threat or security evaluation engines.

### Registry Responsibilities
- Tool discovery and lookup by identifier.
- Action validation against registered method definitions.
- Required argument verification and schema checking.
- Dynamic administrative enablement and disablement (`disable_tool()` / `enable_tool()`).
- Tool execution constraints (execution timeout seconds and maximum output size limits).

---

## 2. Phase 6 Demonstration Adapters

Phase 6 provides four secure demonstration adapters that implement real, sandboxed logic without external network dependencies or unrestricted system access:

### 1. `calculator` (v1.0.0)
- **Category:** `API` | **Risk:** `LOW` | **Timeout:** 5.0s | **Max Output:** 16 KB
- **Actions:**
  - `add`: Add two numbers `a` and `b`.
  - `subtract`: Subtract `b` from `a`.
  - `multiply`: Multiply `a` and `b`.
  - `divide`: Divide `a` by `b`. Rejects division by zero with `INVALID_ARGUMENTS`.

### 2. `sandbox_fs` (v1.0.0)
- **Category:** `FILESYSTEM` | **Risk:** `MEDIUM` | **Timeout:** 5.0s | **Max Output:** 64 KB
- **Sandbox Root:** Strict root at `./.sandbox_workspace`.
- **Security Boundaries:**
  - Strict path resolution (`Path.resolve().relative_to(sandbox_root)`) rejecting all relative escapes (`../`, `..\\`) and symlink directory traversal.
  - Whitelisted file extensions: `.txt`, `.json`, `.csv`, `.md`, `.log`. Attempts to write `.sh`, `.exe`, `.py` are rejected with `INVALID_ARGUMENTS`.
  - File size cap: 2 MB write limit per file.
- **Actions:**
  - `create_file`: Writes content to path within sandbox.
  - `read_file`: Reads content from path within sandbox.
  - `modify_file`: Overwrites or appends to existing file within sandbox.
  - `list_files`: Returns list of files and metadata in a sandbox subdirectory.

### 3. `mock_email` (v1.0.0)
- **Category:** `EXTERNAL_INTEGRATION` | **Risk:** `HIGH` | **Timeout:** 5.0s | **Max Output:** 32 KB
- **Security Boundaries:**
  - Completely simulated in-memory storage; no outbound SMTP or external mail connectivity.
  - Validates recipient email syntax.
- **Actions:**
  - `create_draft`: Creates and stores a local email draft with `to`, `subject`, `body`.
  - `send_email`: Simulates email dispatch and logs delivery event.

### 4. `mock_http` (v1.0.0)
- **Category:** `NETWORK` | **Risk:** `HIGH` | **Timeout:** 5.0s | **Max Output:** 32 KB
- **Security Boundaries:**
  - Strictly rejects all absolute external URLs (`http://`, `https://`, `//`) to prevent SSRF or unauthorized egress.
  - Only serves predefined, simulated mock endpoints:
    - `/weather`: Returns static mock weather data.
    - `/status`: Returns system operational status.
    - `/rates`: Returns mock currency exchange rates.
- **Actions:**
  - `get`: Queries an allowed mock endpoint.
  - `post`: Simulates a POST payload to an allowed mock endpoint.

---

## 3. BaseToolAdapter Lifecycle

All adapters inherit from `BaseToolAdapter` (`agentshield.execution.adapters.base.BaseToolAdapter`), which wraps `run_action()` in:
1. **Wall-clock timer measurement:** Precise millisecond execution time logging.
2. **Output size validation:** JSON serialization check ensuring results do not exceed `max_output_bytes`.
3. **Normalized exception handling:** Translating Python exceptions into structured `ToolExecutionResult` models with sanitized error codes and messages.
