# ADR 0004: Scanner Extensibility

## Status

Accepted

## Context

AI security risks include both simple string patterns and domain-specific configuration issues.

## Decision

Use YAML rules for configurable textual checks and dedicated analyzer crates for domain logic such as secrets, MCP configuration, jailbreak patterns, and GitHub Actions workflows.

## Consequences

- Rule authors can add coverage without recompiling.
- Complex detection logic can use Rust tests and typed helpers.
- Public finding output remains stable even as analyzers evolve.
