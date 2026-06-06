# ADR 0001: Rust Workspace

## Status

Accepted

## Context

Sentinel needs fast local scanning, cross-platform binaries, deterministic CI behavior, and reusable analysis components.

## Decision

Use a Rust Cargo workspace with one CLI binary and focused crates for scanner orchestration, findings, rules, analyzers, and reports.

## Consequences

- Analysis logic can be tested independently.
- The CLI remains thin and mostly handles user interaction.
- Adding new scanners requires explicit crate boundaries and report schema compatibility.
