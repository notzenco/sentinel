# Changelog

All notable changes to Sentinel are documented here.

## v0.1.3 - 2026-06-07

### Fixed

- Fixed release smoke job invocation for Unix install scripts.
- Fixed Windows release zip layout and installer lookup for `sentinel.exe`.

## v0.1.2 - 2026-06-07

### Added

- CLI finding filters: `--severity`, `--only-rule`, and `--exclude-rule` for scan, CI, Claude, and Cursor commands.
- `sentinel rules validate <path>` for checking YAML rule packs before CI use.
- Release smoke jobs that install published Linux, macOS, and Windows archives and run a basic command check.

### Changed

- Dangerous MCP tool detections are consolidated to one finding per file with all dangerous tools listed in the description.
- GitHub workflow actions were updated to current major versions.

## v0.1.1 - 2026-06-07

### Added

- Shared AI config discovery for MCP, Claude Code, Cursor, OpenAI Agents, LangGraph, CrewAI, AutoGen, and generic agent files.
- Structured parsing for JSON, YAML, TOML, and fenced Markdown-adjacent config blocks.
- Low-noise detections for dangerous tool allowlists, broad permissions, approval bypass, unbounded autonomy, and explicit upload/webhook destinations.
- New stable built-in rule ids in the `AGENT###` and `EXFIL###` families.
- AI config fixtures and documentation for supported config patterns.

### Changed

- Expanded MCP and agent tool coverage while keeping generic source files out of the config analyzer.
- Extended scanner deduplication for overlapping autonomy and exfiltration findings.
- Updated package metadata to the `notzenco/sentinel` repository.

## v0.1.0 - 2026-06-06

### Added

- Offline-first Rust scanner workspace and `sentinel` CLI.
- Prompt injection, jailbreak, secret leakage, MCP, agent, and GitHub Actions checks.
- YAML v1 rule engine with text, regex, tool-name, config-key, path, and extension matching.
- Terminal, JSON, SARIF 2.1.0, and self-contained HTML reports.
- Config file loading with excludes, file-size limits, and local suppressions.
- GitHub Action, CI workflow, release packaging workflow, and install scripts.
- Architecture docs, ADRs, threat model, roadmap, security policy, and examples.
