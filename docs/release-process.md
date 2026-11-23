# AgentShield AI — Release Management Process

This document defines the formal release process, versioning scheme, and artifact validation requirements for AgentShield AI.

---

## 1. Semantic Versioning

AgentShield follows Semantic Versioning 2.0.0 (`MAJOR.MINOR.PATCH`):
- **MAJOR**: Breaking API contract changes, fundamental changes to decision semantics.
- **MINOR**: New agent framework integrations, new threat detectors, desktop UI capabilities.
- **PATCH**: Security patches, bug fixes, performance optimizations.

---

## 2. Release Checklist

1. [ ] **Pre-Release Audit**: Complete automated code linting, static analysis, and security checks.
2. [ ] **Regression Verification**: Full test suite pass across all supported Python versions (3.11, 3.12, 3.13, 3.14).
3. [ ] **Red-Team Suite**: Execute automated red-team injection and bypass attack suites.
4. [ ] **Artifact Generation**:
   - Build PyInstaller Desktop bundle (`scripts/build_desktop.py`).
   - Package Windows Inno Setup installer (`scripts/build_installer.ps1`).
   - Build production Docker image.
   - Generate CycloneDX Software Bill of Materials (SBOM).
5. [ ] **Checksum Sign-off**: Compute SHA-256 checksums for all release archives in `dist/`.
6. [ ] **Publish Release**: Tag git commit (`vX.Y.Z`) and trigger `.github/workflows/release.yml`.
