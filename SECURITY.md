# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | Yes                |
| 1.0.x   | Yes                |
| < 1.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in AbuseCLI, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

You can report vulnerabilities through either of the following channels:

- **GitHub Security Advisories**: Open a private security advisory at [https://github.com/LouisDecourtis/AbuseCLI/security/advisories/new](https://github.com/LouisDecourtis/AbuseCLI/security/advisories/new)
- **Email**: Contact the maintainer, Louis Decourtis, directly via GitHub

## What to Expect

After submitting a report, you can expect the following:

1. **Acknowledgment** within 48 hours confirming receipt of your report.
2. **Initial assessment** within 7 days, including whether the report is accepted or requires further information.
3. **Resolution timeline** communicated once the issue has been confirmed and scoped.
4. **Credit** in the release notes, unless you prefer to remain anonymous.

## Scope

The following are considered security issues:

- Exposure or leakage of API keys (e.g., AbuseIPDB API key)
- Command injection or arbitrary code execution
- Insecure handling or storage of credentials and configuration files
- Dependency vulnerabilities that are exploitable in the context of AbuseCLI
- Insecure network communication (e.g., failure to validate TLS)

The following are **not** considered security issues:

- Bugs that do not have a security impact
- Issues in third-party services (e.g., AbuseIPDB API itself)
- Feature requests or general feedback

## Disclosure Policy

We follow a coordinated disclosure process. Please allow a reasonable amount of time for the vulnerability to be addressed before disclosing it publicly.
