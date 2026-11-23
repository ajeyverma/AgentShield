# Sensitive Data Exposure & Data Leakage Detection

The **Data Leakage Detector** (`DET-DATA-002`) identifies cleartext credentials, private keys, API secrets, and sensitive documents in tool arguments and outbound network requests.

---

## 1. Secret Detection Patterns

The engine detects:
- **API Keys:** OpenAI (`sk-...`), Anthropic (`sk-ant-...`), AWS Access Keys (`AKIA...`), AWS Secret Keys.
- **Tokens & Credentials:** JWT tokens (`eyJ...`), Bearer tokens, database connection URLs with embedded passwords.
- **Cryptographic Keys:** RSA and EC private key headers (`-----BEGIN RSA PRIVATE KEY-----`).
- **PII:** Credit card sequences (with pattern checks) and US Social Security Numbers.
- **Sensitive Key Stores:** Targets pointing to `.env`, `id_rsa`, `credentials.json`, `~/.aws/credentials`.

---

## 2. Redaction & Privacy Guarantees

> [!IMPORTANT]
> AgentShield strictly guarantees that **raw secret values are never logged, persisted in the database, or broadcast via WebSockets**.

When a secret is detected:
1. The secret value is masked (e.g., `[OPENAI_API_KEY:...ghij]`).
2. Only the secret type, affected key/argument name, and redacted snippet are retained in the finding evidence.
3. If secrets appear in an outbound network tool call (e.g., `http_post`, `send_email`), the severity is automatically escalated to **CRITICAL**.
