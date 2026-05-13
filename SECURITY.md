# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Email:** [security@caseware.com](mailto:security@caseware.com)

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 3 business days and aim to provide an initial assessment within 10 business days.

## Scope

This policy covers the action source code (`create-passive-dast-map/action.yml`, `analyze-pcap-dast/action.yml`, `scripts/flows-to-sitemap.py`, `scripts/generate-zap-plan.py`, `scripts/count-sarif-alerts.py`, `scripts/fix-sarif-uris.py`, `scripts/burp-xml-stats.py`) and the GitHub Actions workflow configurations in this repository.

Vulnerabilities in third-party components (mitmproxy, OWASP ZAP, Docker images) should be reported to their respective maintainers.

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1 (latest) | Yes |
