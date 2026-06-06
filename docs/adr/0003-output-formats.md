# ADR 0003: Output Formats

## Status

Accepted

## Context

Sentinel must be useful locally, in CI, and in GitHub code scanning.

## Decision

Support terminal, JSON, SARIF 2.1.0, and self-contained HTML reports from the same `ScanReport` structure.

## Consequences

- The finding schema is the source of truth for all outputs.
- SARIF uploads can integrate with GitHub Security.
- HTML reports can be reviewed without a dashboard.
