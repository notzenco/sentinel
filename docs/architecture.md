# Architecture

Sentinel is organized as a Rust workspace with a thin CLI and focused analysis crates. The scanner is deterministic and offline-first.

## Data Flow

1. The CLI resolves the target, profile, config, output format, and fail threshold.
2. `sentinel-scanner` walks text files with gitignore support.
3. Each analyzer receives the relative path and file contents.
4. Built-in analyzers emit structured findings with stable rule ids.
5. `sentinel-rules` loads YAML rules and applies configured text, regex, path, and extension matches.
6. `sentinel-findings` sorts findings, calculates severity counts, and scores the scan.
7. Output crates render terminal, JSON, SARIF, or HTML.

## Trust Boundaries

- Repository files, prompts, MCP configuration, and workflow files are untrusted input.
- Rule files are local configuration. Invalid rules fail closed with an error.
- Reports are generated locally and must not contain raw secret values.
- SARIF and HTML outputs are artifacts; callers decide whether to upload or publish them.

## Extensibility

New risk categories should be added as analyzer crates when they need domain logic, parsing, or tests. Simple textual checks should start as YAML rules. Shared report shape changes belong in `sentinel-findings` and require tests across JSON, SARIF, and HTML rendering.
