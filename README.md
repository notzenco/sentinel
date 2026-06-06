# Sentinel

Sentinel is an offline-first security scanner for AI applications, agents, prompts, MCP servers, workflow files, and repository configuration. It is designed for the AI security risks that traditional application scanners usually miss: prompt injection, jailbreak content, secret leakage, unsafe tool exposure, excessive agent permissions, and risky automation.

## Install from source

```bash
cargo install --path apps/cli
```

## Usage

```bash
sentinel scan .
sentinel scan prompts/ --json
sentinel scan mcp/ --sarif --output sentinel.sarif
sentinel scan . --html --output report.html
sentinel ci . --fail-on high
sentinel claude .
sentinel cursor .
```

## What Sentinel Detects

- Prompt injection phrases such as instruction overrides, system prompt disclosure requests, and tool coercion.
- Jailbreak attempts such as unrestricted roleplay, policy evasion, and stay-in-character chains.
- Secrets including OpenAI, Anthropic, GitHub, AWS, database URLs, JWTs, Azure storage connection strings, and high-entropy secret assignments.
- MCP and agent risks including dangerous tools, unrestricted filesystem/network access, root execution, database admin access, recursive self-calls, and unbounded execution.
- GitHub Actions risks including `pull_request_target`, broad token permissions, remote script execution, and mutable action references.

Sentinel does not upload source code or prompts. The first implementation is deterministic and offline.

## Output Formats

Terminal output is the default and includes a score, severity counts, and a finding table.

JSON output uses this stable shape:

```json
{
  "tool": "sentinel",
  "version": "0.1.0",
  "summary": {
    "target": ".",
    "scanned_files": 12,
    "findings_count": 1,
    "score": 85
  },
  "findings": [
    {
      "id": "SENT-0001",
      "rule_id": "PROMPT001",
      "title": "Prompt instruction override",
      "description": "The prompt contains language that attempts to override higher-priority instructions.",
      "severity": "high",
      "confidence": "high",
      "category": "prompt_injection",
      "location": { "path": "prompts/system.md", "line": 1, "column": 1 },
      "recommendation": "Treat this content as untrusted input and isolate it from system or developer instructions."
    }
  ]
}
```

SARIF output targets GitHub code scanning. HTML output creates a self-contained report file.

## Rules

Rules are YAML files under `rules/` and use `version: 1`.

```yaml
version: 1
id: MCP001
name: Dangerous Shell Execution
category: mcp_security
severity: critical
confidence: high
description: Detects command execution tools exposed through MCP.
recommendation: Remove the tool or restrict it with explicit approval and allowlists.
match:
  regex:
    - '(?i)"name"\s*:\s*"execute_shell"'
  path_contains:
    - mcp
```

Supported match fields are `text`, `regex`, `file_extensions`, `path_contains`, `tool_name`, and `config_key`. Sentinel emits at most one finding per rule per file so multi-pattern rules do not flood reports.

## Configuration

Sentinel automatically loads `sentinel.yml` from the working directory when present. Use `--config <file>` to select a specific config file.

```yaml
rules_dir: rules
exclude:
  - target/**
  - examples/**
  - rules/**
max_file_bytes: 2097152
```

Relative `rules_dir` values resolve from the config file directory. Exclude patterns match repository-relative paths.

Use a local suppression only for intentional fixtures or documented examples:

```text
sentinel:ignore PROMPT001 documented red-team fixture
```

Suppressions apply to the line containing the directive and the immediately following line. A directive may name a rule id, category, or `all`.

## GitHub Actions

Use the repository action in a workflow:

```yaml
name: Sentinel

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sentinel-security/action@v1
        with:
          path: .
          fail-on: high
          sarif-output: sentinel.sarif
```

For this source tree, use `uses: ./` after checkout.

## Project Layout

```text
apps/cli                 CLI binary
crates/scanner           scan orchestration
crates/findings          public finding/report types
crates/rules             YAML rule parsing and text matching
crates/prompt-analysis   prompt injection checks
crates/jailbreak-analysis jailbreak checks
crates/secret-analysis   secret and entropy checks
crates/mcp-analysis      MCP and agent configuration checks
crates/github-actions    workflow checks
crates/sarif             SARIF 2.1.0 output
crates/html-report       self-contained HTML reports
rules/                   default rule pack
docs/                    architecture, threat model, ADRs
```

## Development

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
