# Threat Model

## Assets

- Source code, prompts, and configuration scanned by Sentinel.
- Secrets that may exist in repositories or environment files.
- Findings and generated reports.
- CI tokens and SARIF upload credentials.

## Adversaries

- External contributors submitting pull requests with malicious workflows or prompt payloads.
- Attackers attempting to hide prompt injection or secret leakage in repository content.
- Malicious dependencies or actions referenced from workflow files.
- Users accidentally publishing reports containing sensitive content.

## In-Scope Risks

- Prompt injection and indirect prompt injection in trusted prompt files.
- Jailbreak payloads committed as prompts or test fixtures.
- Secrets committed to repository text.
- MCP tools that expose shell, filesystem, network, or database capabilities without limits.
- Agent configs with unbounded retries, recursive self-calls, or automatic approval.
- GitHub Actions workflows that run untrusted code with broad permissions.

## Out-of-Scope for Phase 1

- Runtime monitoring of live agents.
- Dynamic exploit execution against MCP servers.
- Cloud-hosted scan aggregation.
- LLM-assisted classification.

## Security Requirements

- Scans must be local and deterministic.
- Secret findings must not echo secret values.
- CI failure thresholds must be explicit and predictable.
- Rule parsing errors must fail the scan rather than silently skipping malformed local rules.
- Generated HTML must escape report content.
