# AI Config Detection

Sentinel v0.1.1 adds a shared discovery layer for common AI agent and coding-assistant configuration files. The goal is low-noise structured parsing: findings require explicit dangerous capability, broad permission, unbounded autonomy, or an external send/upload destination.

## Supported Families

| Family | Common paths | Structured signals |
| --- | --- | --- |
| MCP | `mcp/`, MCP server JSON/YAML/TOML | server maps, tools, commands, permissions |
| Claude Code | `.claude/`, `CLAUDE.md`, Claude desktop config | MCP server definitions, tool lists, approval settings |
| Cursor | `.cursor/`, `.mdc` rule files | fenced JSON/YAML/TOML config blocks |
| OpenAI Agents | `agents/`, `openai/` | model, instructions, tools, handoffs, tool choice |
| LangGraph | `langgraph.json`, `langgraph/` | graphs, nodes, edges, recursion limits |
| CrewAI | `crew.yaml`, `crewai/` | agents, tasks, process, tools, iteration limits |
| AutoGen | `autogen/` | assistant agents, group chat, human input mode, code execution config |

Markdown-adjacent files are parsed only when they contain fenced `json`, `yaml`, `yml`, or `toml` blocks. Generic source files are not treated as AI config just because they mention a risky word.

## Finding Families

- `MCP###`: dangerous MCP or tool exposure.
- `AGENT###`: unbounded loops, recursive self-calls, auto-approval, and broad agent permissions.
- `EXFIL###`: explicit external webhook, callback, upload, export, or automatic file-upload behavior.

Sentinel ignores local callback URLs such as localhost during structured exfiltration checks. Use an explicit suppression only for intentional fixtures:

```text
sentinel:ignore EXFIL001 documented local test fixture
```

## Scanning Examples

Use focused paths when you know where a project keeps assistant config:

```bash
sentinel scan .claude
sentinel cursor .
sentinel scan langgraph.json
sentinel scan crew.yaml
sentinel scan autogen/
```

For monorepos, keep generated and vendored files out of scope with `sentinel.yml`:

```yaml
rules_dir: rules
exclude:
  - target/**
  - node_modules/**
  - .next/**
max_file_bytes: 2097152
```

The scanner remains offline and deterministic. It does not call model providers, package registries, or external policy services to decide whether a finding should be emitted.
