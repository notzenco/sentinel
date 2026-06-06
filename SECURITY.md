# Security Policy

## Supported Versions

Sentinel is pre-1.0. Security fixes are accepted on `main` until versioned releases are established.

## Reporting a Vulnerability

Report security issues privately through the repository security advisory flow when available. If that is unavailable, contact the maintainers without posting exploit details publicly.

Include:

- affected version or commit
- command used to reproduce
- minimal input that demonstrates the issue
- expected and actual behavior
- impact assessment

## Scanner Privacy Model

Sentinel is offline-first. The scanner must not send repository contents, prompts, secrets, or findings to external services during local scans. Future optional network or LLM-assisted features must be explicit opt-in and documented in an ADR before implementation.

## Handling Secrets in Findings

Findings must never include raw secret values. Secret analyzers should report rule id, category, severity, location, and remediation only.
