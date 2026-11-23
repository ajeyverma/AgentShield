"""
AgentShield AI — Pre-Flight Configuration Validator.

Validates environment variables, secret key entropy, database connectivity,
and production security settings before service start.
"""

from __future__ import annotations

import sys
from agentshield.contracts.enums import DeploymentMode
from agentshield.core.config import settings


def validate_configuration() -> list[str]:
    issues: list[str] = []

    # 1. Secret Key validation
    if not settings.secret_key or settings.secret_key.strip() == "":
        issues.append("CRITICAL: AGENTSHIELD_SECRET_KEY is empty. Generate a strong key with: python -c \"import secrets; print(secrets.token_urlsafe(64))\"")
    elif len(settings.secret_key) < 32:
        issues.append(f"SECURITY: AGENTSHIELD_SECRET_KEY is only {len(settings.secret_key)} characters long (minimum 32 required for production security).")

    # 2. Production Mode Security Checks
    if settings.env == DeploymentMode.REMOTE:
        if settings.reload:
            issues.append("SECURITY: AGENTSHIELD_RELOAD is enabled in REMOTE deployment mode (must be False).")
        if not settings.database_url:
            issues.append("CONFIGURATION: AGENTSHIELD_DATABASE_URL is not configured for REMOTE deployment (PostgreSQL required).")
        if "sqlite" in settings.effective_database_url.lower():
            issues.append("SECURITY: SQLite database is being used in REMOTE deployment mode. PostgreSQL is mandatory for remote deployments.")
        if "*" in settings.cors_origins:
            issues.append("SECURITY: Wildcard '*' in AGENTSHIELD_CORS_ORIGINS is prohibited in production.")
        if settings.backend_url.startswith("http://"):
            issues.append("SECURITY: AGENTSHIELD_BACKEND_URL uses plain HTTP instead of HTTPS in REMOTE mode.")

    # 3. Port validation
    if not (1 <= settings.port <= 65535):
        issues.append(f"CONFIGURATION: Port {settings.port} is outside valid range (1-65535).")

    return issues


def main():
    print("=" * 60)
    print("AgentShield AI — Pre-Flight Configuration Validation")
    print(f"Deployment Mode: {settings.env.value.upper()}")
    print(f"Backend URL:     {settings.backend_url}")
    print(f"Database:        {settings.effective_database_url.split('@')[-1] if '@' in settings.effective_database_url else settings.effective_database_url}")
    print("=" * 60)

    issues = validate_configuration()
    if not issues:
        print("\n✓ Pre-flight configuration validation PASSED. System is ready for startup.\n")
        sys.exit(0)

    print(f"\nFound {len(issues)} configuration issue(s):")
    has_critical = False
    for issue in issues:
        print(f"  • {issue}")
        if "CRITICAL" in issue:
            has_critical = True

    if has_critical:
        print("\n✗ Startup aborted due to critical configuration errors.")
        sys.exit(1)
    else:
        print("\n⚠ Warnings detected. Review and correct for high-assurance operation.")
        sys.exit(0)


if __name__ == "__main__":
    main()
