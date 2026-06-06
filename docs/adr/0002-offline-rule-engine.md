# ADR 0002: Offline Rule Engine

## Status

Accepted

## Context

AI security scanning often touches sensitive source code, prompts, and secrets. A useful open-source scanner must work without sending content to a remote service.

## Decision

Phase 1 uses deterministic analyzers and YAML rules only. Rule files use `version: 1` and support text, regex, path, and extension constraints.

## Consequences

- Scans are reproducible and privacy-preserving.
- False positives must be managed through severity, confidence, and rule tuning.
- LLM-assisted analysis remains a future opt-in capability, not a default dependency.
