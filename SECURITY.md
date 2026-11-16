# Security Policy

## Supported Versions

Security updates and patches are actively maintained for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability within PhishGuard SOC, please do **NOT** open a public issue. We appreciate responsible disclosure to help protect users and organizations running this system.

Please follow these steps:
1. Open a **Private Security Advisory** on GitHub via the [Advisories tab](https://github.com/67sdnew-hash/phishing-quarantine/security/advisories/new), or email the project maintainer directly.
2. Include:
   - Type of vulnerability (e.g., SSRF, XSS, Deserialization, Auth bypass)
   - Step-by-step reproduction instructions or proof of concept (PoC)
   - Potential impact on production or SOC environments
   - Suggested mitigations (if known)
3. You will receive an initial response acknowledging receipt within **48 hours**.
4. A security patch and disclosure timeline will be coordinated before any public announcement.

---

## Threat Model & Security Posture

PhishGuard is designed to ingest and detonate untrusted, adversarial email messages:

- **Strict XSS Isolation:** Ingested email bodies and highlighted token spans are rendered with HTML escaping (`escape()` / Django auto-escaping) before presentation in the SOC dashboard.
- **Email Parser Hardening:** RFC-822 `.eml` uploads are processed using Python's standard `email.policy.default` parser in memory without executing embedded scripts or macros.
- **Model Deserialization:** The ML artifact bundle (`joblib`) is isolated within the configured `ML_ARTIFACTS_DIR` and loaded read-only by the worker and web processes.
- **CSRF & Host Protection:** Configured with strict Django CSRF middleware, explicit `CSRF_TRUSTED_ORIGINS`, and domain verification across production environments.
