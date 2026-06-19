# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

Report security issues through [GitHub Security Advisories](https://github.com/agentshield/agentshield/security/advisories/new) on the project repository.

Please include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment (bypass technique, privilege escalation, etc.)
- Suggested fix if available

We aim to respond within 72 hours and publish advisories for confirmed issues.

## Scope

- `agentshield-core` policy engine bypasses
- Shell proxy escape vectors
- Daemon IPC authentication weaknesses
- WASM plugin sandbox escapes