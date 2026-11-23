# Tamper-Evident Audit Integrity & Hash Chaining

## 1. Cryptographic Design

AgentShield enforces append-only, tamper-evident audit logs using continuous SHA-256 hash chaining:

$$H_i = \text{SHA256}(\text{canonical\_payload}_i \parallel H_{i-1})$$

Where $H_0 = 0^{64}$ (genesis hash).

### 1.1 Canonical Payload Serialization
To guarantee deterministic hashing regardless of database representation, each record is serialized canonically:

$$\text{canonical\_payload} = \text{seq}=N \mid \text{prev}=H_{prev} \mid \text{tenant}=T \mid \text{actor}=A \mid \text{action}=Ac \mid \text{target}=Tg \mid \text{result}=R \mid \text{desc}=D \mid \text{time}=Iso$$

---

## 2. Chain Verification Algorithm

The verification process (`TamperEvidentAuditService.verify_chain(tenant_id)`) performs:
1. **Sequence Continuity**: Confirms $S_i = S_{i-1} + 1$ with $S_1 = 1$. Any deletion or insertion breaks sequence numbering.
2. **Previous Hash Continuity**: Confirms $H_{prev, i} == H_{i-1}$. Any reordering breaks previous hash continuity.
3. **Record Content Integrity**: Recomputes $\text{SHA256}(\text{canonical\_payload}_i)$ from raw fields and confirms match with stored $H_i$. Any modification to action, target, result, or description breaks hash matching.

---

## 3. Cryptographic Checkpoints

Periodic or administrative checkpoints anchor verified head states:
- Stores `start_sequence`, `end_sequence`, and `root_hash`.
- Validates chain up to checkpoint sequence before creation.
- Enables accelerated incremental verification.

---

## 4. Threat Model & Limitations

> [!WARNING] Database Administrator (DBA) Access Limitation
> Hash chaining detects unauthorized modifications, record deletions, and record reordering by standard database users and API clients. However, if a malicious adversary possesses superuser/DBA write access to the database AND the signing key/code, they could theoretically rewrite the entire table from a given point onward. To mitigate this in high-assurance deployments, checkpoints should be exported to external WORM (Write Once Read Many) storage or immutable cloud ledger services.
