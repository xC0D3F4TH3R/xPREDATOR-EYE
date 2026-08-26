# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes |
| 1.x     | No |

## Reporting a Vulnerability

If you discover a security vulnerability in xPREDATOR-EYE, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Contact

- **Email**: [Open a private security advisory on GitHub](https://github.com/xC0D3F4TH3R/xPREDATOR-EYE/security/advisories/new)
- **Response Time**: Within 48 hours for initial triage
- **Disclosure**: We follow coordinated disclosure — we will work with you to understand and address the issue before any public disclosure

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Scope

In-scope:
- Code execution vulnerabilities
- Authentication/authorization bypass
- Path traversal or file access issues
- Dependency vulnerabilities
- Information disclosure in reports

Out-of-scope:
- Social engineering
- Physical security
- Issues in third-party dependencies (report upstream)

## Security Best Practices for Users

When running xPREDATOR-EYE:

1. **Never run as root** unless automated response requires elevated privileges
2. **Use `--dry-run`** (default) before enabling `--respond`
3. **Store API keys** in environment variables, not in config files
4. **Restrict quarantine directory** permissions
5. **Review response commands** before executing them against production systems
6. **Run in a lab** before deploying on production networks
