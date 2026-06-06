# Contributing

## Development Setup

Sentinel uses a Rust workspace. Install stable Rust, then run:

```bash
cargo test --workspace
```

Before opening a pull request:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Rule Contributions

Rules live under `rules/` and must use `version: 1`. A rule should include:

- a stable `id`
- clear `name`, `description`, and `recommendation`
- conservative severity and confidence
- tests or example fixtures when the rule covers a new risk class

Rules should avoid matching secrets by value in output. Findings must identify the location and remediation without copying sensitive content into report text.

## Commit Messages

Use Conventional Commits:

```text
feat(scanner): add prompt injection analyzer
fix(secret): avoid duplicate entropy findings
docs(threat-model): document SARIF trust boundary
```

Do not add AI attribution trailers to commit messages or pull request descriptions.
