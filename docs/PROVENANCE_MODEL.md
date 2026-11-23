# Source Provenance Model

AgentShield AI models data lineage and origin trust through the **Provenance Model** (`agentshield/contracts/provenance.py`).

---

## 1. Provenance Context Architecture

AI agents process instructions and data from diverse origins. The provenance model categorizes sources and establishes trust boundaries:

```python
class SourceType(str, Enum):
    USER_INPUT            = "user_input"
    SYSTEM_INSTRUCTION    = "system_instruction"
    DEVELOPER_INSTRUCTION = "developer_instruction"
    WEBPAGE               = "webpage"
    EMAIL                 = "email"
    DOCUMENT              = "document"
    IMAGE_OCR             = "image_ocr"
    TOOL_OUTPUT           = "tool_output"
    EXTERNAL_API          = "external_api"
    DATABASE              = "database"
    UNKNOWN               = "unknown"

class TrustLevel(str, Enum):
    TRUSTED   = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN   = "UNKNOWN"
```

---

## 2. Trust Propagation Rules

1. **Explicit Ingestion Assignment:** Trust levels are assigned by trusted server-side connectors or integration adapters at the ingestion boundary. An agent's self-reported claim of "trusted" is never accepted.
2. **Untrusted Contamination:** If an `ActionRequest` incorporates data from any `UNTRUSTED` source (or if provenance is absent/`UNKNOWN`), the effective context is considered untrusted (`is_untrusted == True`).
3. **External Untrusted Origins:** Content from `webpage`, `email`, `document`, and `external_api` is untrusted by default unless authenticated with cryptographic integrity.
