use regex::Regex;
use sentinel_common::line_col_for_offset;
use sentinel_findings::{Category, Confidence, Finding, Location, Severity};
use sentinel_rules::FindingIdAllocator;
use serde_json::Value;
use std::collections::HashSet;

const DANGEROUS_TOOL_NAMES: &[&str] = &[
    "execute_shell",
    "exec",
    "shell",
    "run_command",
    "run_cmd",
    "delete_file",
    "write_file",
    "read_file",
    "filesystem",
    "database_admin",
];

const PERMISSION_PATTERNS: &[(&str, &str, Severity)] = &[
    (
        r#"(?i)(filesystem|fs|file_system).{0,80}(\*|unrestricted|readwrite|read-write|full)"#,
        "Unrestricted filesystem access",
        Severity::Critical,
    ),
    (
        r#"(?i)(network|internet|http).{0,80}(\*|unrestricted|all|any)"#,
        "Unrestricted network access",
        Severity::High,
    ),
    (
        r#"(?i)(root|sudo|administrator|admin).{0,80}(true|enabled|allow)"#,
        "Privileged command execution",
        Severity::Critical,
    ),
    (
        r#"(?i)(database|db).{0,80}(admin|drop|delete|superuser|owner)"#,
        "Database administrative access",
        Severity::High,
    ),
];

pub fn analyze_mcp_file(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    if !looks_like_mcp_path(relative_path, contents) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let structured = parse_structured_value(relative_path, contents);
    findings.extend(detect_dangerous_tools(
        relative_path,
        contents,
        structured.as_ref(),
        id_allocator,
    ));
    findings.extend(detect_permissions(
        relative_path,
        contents,
        structured.as_ref(),
        id_allocator,
    ));
    findings.extend(detect_agent_autonomy(
        relative_path,
        contents,
        structured.as_ref(),
        id_allocator,
    ));
    findings
}

fn detect_dangerous_tools(
    relative_path: &str,
    contents: &str,
    structured: Option<&Value>,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut matched_tools = HashSet::new();

    if let Some(value) = structured {
        collect_dangerous_structured_tools(value, &mut matched_tools);
        for tool in &matched_tools {
            findings.push(dangerous_tool_finding(
                relative_path,
                contents,
                tool,
                id_allocator,
            ));
        }
    }

    for tool in DANGEROUS_TOOL_NAMES {
        if matched_tools.contains(*tool) {
            continue;
        }

        let regex = Regex::new(&format!(
            r#"(?i)["']?(name|tool|function_name|command)["']?\s*[:=]\s*["']?{}\b["']?"#,
            regex::escape(tool)
        ))
        .expect("dangerous tool regex must compile");

        if regex.find(contents).is_some() {
            findings.push(dangerous_tool_finding(
                relative_path,
                contents,
                tool,
                id_allocator,
            ));
        }
    }
    findings
}

fn detect_permissions(
    relative_path: &str,
    contents: &str,
    structured: Option<&Value>,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(value) = structured {
        collect_structured_permissions(value, relative_path, contents, id_allocator, &mut findings);
    }

    for (pattern, title, severity) in PERMISSION_PATTERNS {
        let regex = Regex::new(pattern).expect("permission regex must compile");
        if let Some(matched) = regex.find(contents) {
            findings.push(permission_finding(
                relative_path,
                contents,
                matched.start(),
                title,
                *severity,
                id_allocator,
            ));
        }
    }
    findings
}

fn detect_agent_autonomy(
    relative_path: &str,
    contents: &str,
    structured: Option<&Value>,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    if let Some(value) = structured {
        if let Some((key, title, severity)) = find_structured_autonomy(value) {
            return vec![autonomy_finding(
                relative_path,
                contents,
                &key,
                title,
                severity,
                id_allocator,
            )];
        }
    }

    let patterns = [
        r"(?i)(max_iterations|max_steps|max_retries)\s*[:=]\s*(-1|0|null|unlimited)",
        r"(?i)(recursive|self_call|self-calling)\s*[:=]\s*(true|enabled|allow)",
        r"(?i)(auto_approve|auto-approve|require_approval)\s*[:=]\s*(true|false)",
    ];

    let mut findings = Vec::new();
    for pattern in patterns {
        let regex = Regex::new(pattern).expect("autonomy regex must compile");
        if let Some(matched) = regex.find(contents) {
            findings.push(autonomy_finding_at_offset(
                relative_path,
                contents,
                matched.start(),
                "Unbounded or unsafe agent autonomy",
                Severity::High,
                id_allocator,
            ));
            break;
        }
    }
    findings
}

fn dangerous_tool_finding(
    relative_path: &str,
    contents: &str,
    tool: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Finding {
    let offset = find_case_insensitive(contents, tool).unwrap_or_default();
    let (line, column) = line_col_for_offset(contents, offset);
    Finding {
        id: id_allocator.next_id(),
        rule_id: "MCP001".to_string(),
        title: "Dangerous MCP tool exposed".to_string(),
        description: format!(
            "The MCP configuration exposes a tool named `{tool}`, which can enable unsafe host access."
        ),
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: Category::McpSecurity,
        location: Location::new(relative_path, Some(line), Some(column)),
        recommendation: "Remove the tool, restrict it behind a narrow allowlist, or require explicit per-call approval.".to_string(),
    }
}

fn permission_finding(
    relative_path: &str,
    contents: &str,
    offset: usize,
    title: &str,
    severity: Severity,
    id_allocator: &mut FindingIdAllocator,
) -> Finding {
    let (line, column) = line_col_for_offset(contents, offset);
    Finding {
        id: id_allocator.next_id(),
        rule_id: "MCP002".to_string(),
        title: title.to_string(),
        description: "The MCP or agent configuration grants broad access that can amplify prompt injection or tool abuse.".to_string(),
        severity,
        confidence: Confidence::Medium,
        category: Category::McpSecurity,
        location: Location::new(relative_path, Some(line), Some(column)),
        recommendation: "Scope permissions to explicit paths, hosts, commands, and database operations needed by the application.".to_string(),
    }
}

fn autonomy_finding(
    relative_path: &str,
    contents: &str,
    key: &str,
    title: &str,
    severity: Severity,
    id_allocator: &mut FindingIdAllocator,
) -> Finding {
    let offset = find_case_insensitive(contents, key).unwrap_or_default();
    autonomy_finding_at_offset(
        relative_path,
        contents,
        offset,
        title,
        severity,
        id_allocator,
    )
}

fn autonomy_finding_at_offset(
    relative_path: &str,
    contents: &str,
    offset: usize,
    title: &str,
    severity: Severity,
    id_allocator: &mut FindingIdAllocator,
) -> Finding {
    let (line, column) = line_col_for_offset(contents, offset);
    Finding {
        id: id_allocator.next_id(),
        rule_id: "AGENT001".to_string(),
        title: title.to_string(),
        description: "The agent configuration may allow unbounded execution, recursive calls, or automatic approval.".to_string(),
        severity,
        confidence: Confidence::Medium,
        category: Category::AgentSecurity,
        location: Location::new(relative_path, Some(line), Some(column)),
        recommendation: "Set explicit execution limits, disable recursive self-calls, and require approval for sensitive tools.".to_string(),
    }
}

fn parse_structured_value(relative_path: &str, contents: &str) -> Option<Value> {
    let path = relative_path.to_ascii_lowercase();
    if path.ends_with(".json") {
        serde_json::from_str(contents).ok()
    } else if path.ends_with(".yaml") || path.ends_with(".yml") {
        serde_yaml::from_str::<serde_yaml::Value>(contents)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
    } else if path.ends_with(".toml") {
        toml::from_str::<toml::Value>(contents)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
    } else {
        None
    }
}

fn collect_dangerous_structured_tools(value: &Value, matched_tools: &mut HashSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let key = normalize_key(key);
                if matches!(key.as_str(), "name" | "tool" | "function_name" | "command") {
                    if let Some(tool) = value.as_str() {
                        if is_dangerous_tool(tool) {
                            matched_tools.insert(tool.to_ascii_lowercase());
                        }
                    }
                }

                if matches!(
                    key.as_str(),
                    "tools" | "allowed_tools" | "tool_allowlist" | "functions" | "commands"
                ) {
                    collect_tool_values(value, matched_tools);
                }

                collect_dangerous_structured_tools(value, matched_tools);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_dangerous_structured_tools(value, matched_tools);
            }
        }
        _ => {}
    }
}

fn collect_tool_values(value: &Value, matched_tools: &mut HashSet<String>) {
    match value {
        Value::String(tool) if is_dangerous_tool(tool) => {
            matched_tools.insert(tool.to_ascii_lowercase());
        }
        Value::Array(values) => {
            for value in values {
                collect_tool_values(value, matched_tools);
            }
        }
        Value::Object(_) => collect_dangerous_structured_tools(value, matched_tools),
        _ => {}
    }
}

fn collect_structured_permissions(
    value: &Value,
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
    findings: &mut Vec<Finding>,
) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let normalized = normalize_key(key);
                if let Some((title, severity)) = classify_permission(&normalized, value) {
                    let offset = find_case_insensitive(contents, key).unwrap_or_default();
                    findings.push(permission_finding(
                        relative_path,
                        contents,
                        offset,
                        title,
                        severity,
                        id_allocator,
                    ));
                }
                collect_structured_permissions(
                    value,
                    relative_path,
                    contents,
                    id_allocator,
                    findings,
                );
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_structured_permissions(
                    value,
                    relative_path,
                    contents,
                    id_allocator,
                    findings,
                );
            }
        }
        _ => {}
    }
}

fn classify_permission(key: &str, value: &Value) -> Option<(&'static str, Severity)> {
    if (key.contains("filesystem") || key == "fs" || key.contains("file_system"))
        && value_is_broad(value)
    {
        return Some(("Unrestricted filesystem access", Severity::Critical));
    }

    if (key.contains("network") || key.contains("internet") || key.contains("http"))
        && (value_is_broad(value) || value.as_bool() == Some(true))
    {
        return Some(("Unrestricted network access", Severity::High));
    }

    if (key.contains("root") || key.contains("sudo") || key.contains("administrator"))
        && value_is_enabled(value)
    {
        return Some(("Privileged command execution", Severity::Critical));
    }

    if (key.contains("database") || key == "db")
        && value_mentions_any(value, &["admin", "drop", "delete", "superuser", "owner"])
    {
        return Some(("Database administrative access", Severity::High));
    }

    None
}

fn find_structured_autonomy(value: &Value) -> Option<(String, &'static str, Severity)> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let normalized = normalize_key(key);
                if matches!(
                    normalized.as_str(),
                    "max_iterations" | "max_steps" | "max_retries"
                ) && value_is_unbounded(value)
                {
                    return Some((
                        key.clone(),
                        "Unbounded agent execution limit",
                        Severity::High,
                    ));
                }

                if matches!(
                    normalized.as_str(),
                    "recursive" | "self_call" | "self_calling"
                ) && value_is_enabled(value)
                {
                    return Some((key.clone(), "Recursive agent self-calling", Severity::High));
                }

                if normalized == "auto_approve" && value_is_enabled(value) {
                    return Some((
                        key.clone(),
                        "Automatic tool approval enabled",
                        Severity::High,
                    ));
                }

                if normalized == "require_approval" && value.as_bool() == Some(false) {
                    return Some((
                        key.clone(),
                        "Tool approval requirement disabled",
                        Severity::High,
                    ));
                }

                if let Some(found) = find_structured_autonomy(value) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(find_structured_autonomy),
        _ => None,
    }
}

fn is_dangerous_tool(tool: &str) -> bool {
    let normalized = normalize_key(tool);
    DANGEROUS_TOOL_NAMES
        .iter()
        .any(|candidate| normalize_key(candidate) == normalized)
}

fn value_is_broad(value: &Value) -> bool {
    value_mentions_any(
        value,
        &[
            "*",
            "unrestricted",
            "readwrite",
            "read-write",
            "full",
            "all",
            "any",
        ],
    )
}

fn value_is_enabled(value: &Value) -> bool {
    value.as_bool() == Some(true)
        || value
            .as_str()
            .map(|text| matches!(normalize_key(text).as_str(), "true" | "enabled" | "allow"))
            .unwrap_or(false)
}

fn value_is_unbounded(value: &Value) -> bool {
    value.as_i64().map(|number| number <= 0).unwrap_or(false)
        || value
            .as_str()
            .map(|text| {
                matches!(
                    normalize_key(text).as_str(),
                    "unlimited" | "none" | "null" | "0" | "-1"
                )
            })
            .unwrap_or(false)
        || value.is_null()
}

fn value_mentions_any(value: &Value, needles: &[&str]) -> bool {
    match value {
        Value::String(text) => {
            let normalized = normalize_key(text);
            needles.iter().any(|needle| normalized.contains(needle))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| value_mentions_any(value, needles)),
        Value::Object(map) => map.iter().any(|(key, value)| {
            let normalized_key = normalize_key(key);
            needles.iter().any(|needle| normalized_key.contains(needle))
                || value_mentions_any(value, needles)
        }),
        Value::Bool(value) => *value && needles.contains(&"true"),
        Value::Number(number) => needles.iter().any(|needle| number.to_string() == *needle),
        Value::Null => needles.contains(&"null"),
    }
}

fn find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn normalize_key(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .replace('-', "_")
        .to_ascii_lowercase()
}

fn looks_like_mcp_path(relative_path: &str, contents: &str) -> bool {
    let path = relative_path.to_ascii_lowercase();
    if !is_supported_mcp_file(&path) {
        return false;
    }

    path.contains("mcp")
        || path.contains("agent")
        || path.contains("tool")
        || contents
            .to_ascii_lowercase()
            .contains("modelcontextprotocol")
        || contents.to_ascii_lowercase().contains("\"tools\"")
}

fn is_supported_mcp_file(path: &str) -> bool {
    path.ends_with(".json")
        || path.ends_with(".yaml")
        || path.ends_with(".yml")
        || path.ends_with(".toml")
        || path.ends_with(".md")
        || path.ends_with(".mdc")
        || path.ends_with(".txt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_dangerous_mcp_tool() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "mcp/server.json",
            r#"{ "tools": [{ "name": "execute_shell" }] }"#,
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "MCP001"));
    }

    #[test]
    fn detects_unrestricted_filesystem_permission() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "agent.yml",
            "permissions:\n  filesystem: unrestricted",
            &mut ids,
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Unrestricted filesystem access")
        );
    }

    #[test]
    fn skips_rust_source_files() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "crates/mcp-analysis/src/lib.rs",
            r#"{ "tools": [{ "name": "execute_shell" }] }"#,
            &mut ids,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn detects_tool_allowlist_arrays() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "agent.json",
            r#"{ "allowed_tools": ["read_file", "execute_shell"] }"#,
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "MCP001"));
    }

    #[test]
    fn detects_structured_agent_autonomy() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "agent.toml",
            "auto_approve = true\nmax_iterations = 0",
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "AGENT001"));
    }

    #[test]
    fn detects_structured_database_admin_access() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "agent.yaml",
            "permissions:\n  database:\n    role: admin",
            &mut ids,
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Database administrative access")
        );
    }
}
