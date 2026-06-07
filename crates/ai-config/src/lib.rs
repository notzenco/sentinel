use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiConfigKind {
    Mcp,
    Claude,
    Cursor,
    OpenAiAgents,
    LangGraph,
    CrewAi,
    AutoGen,
    GenericAgent,
}

impl Display for AiConfigKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            AiConfigKind::Mcp => "mcp",
            AiConfigKind::Claude => "claude",
            AiConfigKind::Cursor => "cursor",
            AiConfigKind::OpenAiAgents => "openai_agents",
            AiConfigKind::LangGraph => "langgraph",
            AiConfigKind::CrewAi => "crewai",
            AiConfigKind::AutoGen => "autogen",
            AiConfigKind::GenericAgent => "generic_agent",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiConfigFile {
    pub kind: AiConfigKind,
    pub relative_path: String,
    pub structured_values: Vec<Value>,
}

impl AiConfigFile {
    pub fn has_structured_values(&self) -> bool {
        !self.structured_values.is_empty()
    }
}

pub fn discover_ai_config(relative_path: &str, contents: &str) -> Option<AiConfigFile> {
    let path = normalize_path(relative_path);
    if !is_supported_config_file(&path) {
        return None;
    }

    let structured_values = parse_structured_values(&path, contents);
    let kind = detect_kind(&path, contents, &structured_values)?;

    Some(AiConfigFile {
        kind,
        relative_path: relative_path.replace('\\', "/"),
        structured_values,
    })
}

pub fn parse_structured_values(relative_path: &str, contents: &str) -> Vec<Value> {
    let path = normalize_path(relative_path);
    if path.ends_with(".json") {
        return serde_json::from_str(contents).ok().into_iter().collect();
    }

    if path.ends_with(".yaml") || path.ends_with(".yml") {
        return serde_yaml::from_str::<serde_yaml::Value>(contents)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
            .into_iter()
            .collect();
    }

    if path.ends_with(".toml") {
        return toml::from_str::<toml::Value>(contents)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
            .into_iter()
            .collect();
    }

    if is_markdown_like(&path) {
        return parse_fenced_structured_blocks(contents);
    }

    Vec::new()
}

fn detect_kind(path: &str, contents: &str, structured_values: &[Value]) -> Option<AiConfigKind> {
    let lower_contents = contents.to_ascii_lowercase();

    if path.contains(".claude/")
        || path.ends_with("claude.md")
        || path.ends_with("claude_desktop_config.json")
    {
        return Some(AiConfigKind::Claude);
    }

    if path.contains(".cursor/") || path.ends_with(".mdc") {
        return Some(AiConfigKind::Cursor);
    }

    if path.contains("langgraph") || structured_values.iter().any(looks_like_langgraph) {
        return Some(AiConfigKind::LangGraph);
    }

    if path.contains("crewai")
        || path.contains("crew.")
        || structured_values.iter().any(looks_like_crewai)
    {
        return Some(AiConfigKind::CrewAi);
    }

    if path.contains("autogen") || structured_values.iter().any(looks_like_autogen) {
        return Some(AiConfigKind::AutoGen);
    }

    if path.contains("openai")
        || path.contains("agents")
        || structured_values.iter().any(looks_like_openai_agents)
    {
        return Some(AiConfigKind::OpenAiAgents);
    }

    if path.contains("mcp")
        || lower_contents.contains("modelcontextprotocol")
        || lower_contents.contains("mcpservers")
        || structured_values.iter().any(looks_like_mcp)
    {
        return Some(AiConfigKind::Mcp);
    }

    if path.contains("agent")
        || path.contains("tool")
        || structured_values.iter().any(looks_like_generic_agent)
    {
        return Some(AiConfigKind::GenericAgent);
    }

    None
}

fn looks_like_mcp(value: &Value) -> bool {
    object_has_key(value, &["mcpservers", "mcp_servers", "servers"])
        && object_has_key(value, &["command", "args", "tools", "permissions"])
}

fn looks_like_openai_agents(value: &Value) -> bool {
    object_has_key(value, &["instructions", "model", "tools"])
        && object_has_key(
            value,
            &["handoffs", "tool_choice", "response_format", "name"],
        )
}

fn looks_like_langgraph(value: &Value) -> bool {
    object_has_key(
        value,
        &[
            "graphs",
            "nodes",
            "edges",
            "recursion_limit",
            "checkpointer",
        ],
    )
}

fn looks_like_crewai(value: &Value) -> bool {
    object_has_key(value, &["crew", "agents", "tasks", "process"])
        && object_has_key(
            value,
            &["tools", "max_iter", "allow_delegation", "manager_agent"],
        )
}

fn looks_like_autogen(value: &Value) -> bool {
    object_has_key(
        value,
        &[
            "assistant_agent",
            "user_proxy",
            "groupchat",
            "human_input_mode",
            "code_execution_config",
        ],
    )
}

fn looks_like_generic_agent(value: &Value) -> bool {
    object_has_key(
        value,
        &[
            "agent",
            "agents",
            "tools",
            "allowed_tools",
            "permissions",
            "max_iterations",
            "max_steps",
        ],
    )
}

fn object_has_key(value: &Value, keys: &[&str]) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            let normalized = normalize_key(key);
            keys.iter()
                .any(|candidate| normalized == normalize_key(candidate))
                || object_has_key(child, keys)
        }),
        Value::Array(values) => values.iter().any(|value| object_has_key(value, keys)),
        _ => false,
    }
}

fn parse_fenced_structured_blocks(contents: &str) -> Vec<Value> {
    let mut blocks = Vec::new();
    let mut current_language: Option<String> = None;
    let mut current_body = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("```") {
            if let Some(language) = current_language.take() {
                if let Some(value) = parse_block(&language, &current_body) {
                    blocks.push(value);
                }
                current_body.clear();
            } else {
                let language = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if matches!(
                    language.as_str(),
                    "json" | "yaml" | "yml" | "toml" | "jsonc"
                ) {
                    current_language = Some(language);
                }
            }
            continue;
        }

        if current_language.is_some() {
            current_body.push_str(line);
            current_body.push('\n');
        }
    }

    blocks
}

fn parse_block(language: &str, body: &str) -> Option<Value> {
    match language {
        "json" | "jsonc" => serde_json::from_str(body).ok(),
        "yaml" | "yml" => serde_yaml::from_str::<serde_yaml::Value>(body)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok()),
        "toml" => toml::from_str::<toml::Value>(body)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok()),
        _ => None,
    }
}

fn is_supported_config_file(path: &str) -> bool {
    path.ends_with(".json")
        || path.ends_with(".yaml")
        || path.ends_with(".yml")
        || path.ends_with(".toml")
        || is_markdown_like(path)
}

fn is_markdown_like(path: &str) -> bool {
    path.ends_with(".md") || path.ends_with(".mdc") || path.ends_with(".txt")
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn normalize_key(value: &str) -> String {
    value.replace('-', "_").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_claude_mcp_config() {
        let config = discover_ai_config(
            ".claude/mcp.json",
            r#"{ "mcpServers": { "shell": { "command": "npx" } } }"#,
        )
        .unwrap();

        assert_eq!(config.kind, AiConfigKind::Claude);
        assert!(config.has_structured_values());
    }

    #[test]
    fn recognizes_cursor_markdown_config_blocks() {
        let config = discover_ai_config(
            ".cursor/rules/agent.mdc",
            "```yaml\nallowed_tools:\n  - execute_shell\n```\n",
        )
        .unwrap();

        assert_eq!(config.kind, AiConfigKind::Cursor);
        assert_eq!(config.structured_values.len(), 1);
    }

    #[test]
    fn parses_common_config_formats() {
        assert_eq!(
            parse_structured_values("agent.json", r#"{ "tools": [] }"#).len(),
            1
        );
        assert_eq!(
            parse_structured_values("agent.yaml", "tools: []\n").len(),
            1
        );
        assert_eq!(
            parse_structured_values("agent.toml", "tools = []\n").len(),
            1
        );
        assert_eq!(
            parse_structured_values(".cursor/rules/agent.mdc", "```toml\ntools = []\n```\n").len(),
            1
        );
    }

    #[test]
    fn recognizes_framework_config_shapes() {
        assert_eq!(
            discover_ai_config(
                "langgraph.json",
                r#"{ "graphs": { "main": {} }, "recursion_limit": 0 }"#,
            )
            .unwrap()
            .kind,
            AiConfigKind::LangGraph
        );
        assert_eq!(
            discover_ai_config("crew.yaml", "agents:\n  - role: ops\n    tools: []\n")
                .unwrap()
                .kind,
            AiConfigKind::CrewAi
        );
        assert_eq!(
            discover_ai_config("autogen.json", r#"{ "human_input_mode": "NEVER" }"#)
                .unwrap()
                .kind,
            AiConfigKind::AutoGen
        );
    }

    #[test]
    fn ignores_generic_json_without_ai_config_shape() {
        assert!(discover_ai_config("package.json", r#"{ "scripts": {} }"#).is_none());
    }
}
