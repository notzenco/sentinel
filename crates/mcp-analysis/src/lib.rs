use regex::Regex;
use sentinel_ai_config::{AiConfigFile, AiConfigKind, discover_ai_config};
use sentinel_common::line_col_for_offset;
use sentinel_findings::{Category, Confidence, Finding, Location, Severity};
use sentinel_rules::FindingIdAllocator;
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;
use url::Url;

const DANGEROUS_TOOL_NAMES: &[&str] = &[
    "execute_shell",
    "exec",
    "shell",
    "run_command",
    "run_cmd",
    "run_shell",
    "terminal",
    "bash",
    "powershell",
    "cmd",
    "code_interpreter",
    "delete_file",
    "write_file",
    "write_files",
    "read_file",
    "read_files",
    "file_write",
    "file_read",
    "filesystem",
    "execute_sql",
    "run_sql",
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
    let Some(config) = discover_ai_config(relative_path, contents) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    findings.extend(detect_dangerous_tools(
        relative_path,
        contents,
        &config,
        id_allocator,
    ));
    findings.extend(detect_permissions(
        relative_path,
        contents,
        &config,
        id_allocator,
    ));
    findings.extend(detect_agent_autonomy(
        relative_path,
        contents,
        &config,
        id_allocator,
    ));
    findings.extend(detect_exfiltration(
        relative_path,
        contents,
        &config,
        id_allocator,
    ));
    findings
}

fn detect_dangerous_tools(
    relative_path: &str,
    contents: &str,
    config: &AiConfigFile,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut matched_tools = HashSet::new();

    for value in &config.structured_values {
        collect_dangerous_structured_tools(value, &mut matched_tools);
    }

    for tool in &matched_tools {
        findings.push(dangerous_tool_finding(
            relative_path,
            contents,
            tool,
            id_allocator,
        ));
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
    config: &AiConfigFile,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let category = permission_category(relative_path, config);
    for value in &config.structured_values {
        collect_structured_permissions(
            value,
            relative_path,
            contents,
            &category,
            id_allocator,
            &mut findings,
        );
    }

    for (pattern, title, severity) in PERMISSION_PATTERNS {
        let regex = Regex::new(pattern).expect("permission regex must compile");
        if let Some(matched) = regex.find(contents) {
            findings.push(permission_finding(
                relative_path,
                contents,
                matched.start(),
                category.clone(),
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
    config: &AiConfigFile,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    for value in &config.structured_values {
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
        (
            r"(?i)(max_iterations|max_steps|max_retries|max_iter|max_turns|max_loops|loop_limit|recursion_limit)\s*[:=]\s*(-1|0|null|none|unlimited)",
            "Unbounded agent execution limit",
            Severity::High,
        ),
        (
            r"(?i)(recursive|self_call|self-calling)\s*[:=]\s*(true|enabled|allow)",
            "Recursive agent self-calling",
            Severity::High,
        ),
        (
            r"(?i)(auto_approve|auto-approve|auto_approval|auto-approval)\s*[:=]\s*(true|enabled|allow)",
            "Automatic tool approval enabled",
            Severity::High,
        ),
        (
            r"(?i)(require_approval|require-approval)\s*[:=]\s*(false|disabled|never|none)",
            "Tool approval requirement disabled",
            Severity::High,
        ),
        (
            r#"(?i)(approval_policy|approval-policy)\s*[:=]\s*["']?(never|none|disabled)["']?"#,
            "Tool approval requirement disabled",
            Severity::High,
        ),
        (
            r#"(?i)(human_input_mode|human-input-mode)\s*[:=]\s*["']?(never|none|disabled)["']?"#,
            "Human approval disabled for autonomous agent",
            Severity::High,
        ),
    ];

    let mut findings = Vec::new();
    for (pattern, title, severity) in patterns {
        let regex = Regex::new(pattern).expect("autonomy regex must compile");
        if let Some(matched) = regex.find(contents) {
            findings.push(autonomy_finding_at_offset(
                relative_path,
                contents,
                matched.start(),
                title,
                severity,
                id_allocator,
            ));
            break;
        }
    }
    findings
}

fn detect_exfiltration(
    relative_path: &str,
    contents: &str,
    config: &AiConfigFile,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for value in &config.structured_values {
        collect_exfiltration(value, relative_path, contents, id_allocator, &mut findings);
    }

    let webhook_pattern = Regex::new(
        r#"(?i)(webhook_url|callback_url|upload_url|external_url|destination_url)\s*[:=]\s*["']?(https?://[^"'\s]+)"#,
    )
    .expect("webhook regex must compile");
    for captures in webhook_pattern.captures_iter(contents) {
        let Some(url) = captures.get(2) else {
            continue;
        };
        if !is_external_http_url(url.as_str()) {
            continue;
        }
        let matched = captures.get(0).expect("capture 0 exists for webhook regex");
        findings.push(exfil_finding(
            relative_path,
            contents,
            matched.start(),
            "External exfiltration endpoint configured",
            "The AI configuration sends data to an explicit external URL, webhook, callback, or upload endpoint.",
            id_allocator,
        ));
        break;
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
    category: Category,
    title: &str,
    severity: Severity,
    id_allocator: &mut FindingIdAllocator,
) -> Finding {
    let (line, column) = line_col_for_offset(contents, offset);
    let rule_id = if category == Category::AgentSecurity {
        "AGENT005"
    } else {
        "MCP002"
    };
    Finding {
        id: id_allocator.next_id(),
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        description: "The MCP or agent configuration grants broad access that can amplify prompt injection or tool abuse.".to_string(),
        severity,
        confidence: Confidence::Medium,
        category,
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
        rule_id: agent_rule_id(title).to_string(),
        title: title.to_string(),
        description: "The agent configuration may allow unbounded execution, recursive calls, or automatic approval.".to_string(),
        severity,
        confidence: Confidence::Medium,
        category: Category::AgentSecurity,
        location: Location::new(relative_path, Some(line), Some(column)),
        recommendation: "Set explicit execution limits, disable recursive self-calls, and require approval for sensitive tools.".to_string(),
    }
}

fn exfil_finding(
    relative_path: &str,
    contents: &str,
    offset: usize,
    title: &str,
    description: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Finding {
    let (line, column) = line_col_for_offset(contents, offset);
    Finding {
        id: id_allocator.next_id(),
        rule_id: "EXFIL001".to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity: Severity::High,
        confidence: Confidence::High,
        category: Category::DataExfiltration,
        location: Location::new(relative_path, Some(line), Some(column)),
        recommendation: "Require an allowlist for outbound destinations, avoid automatic file upload, and review what data the agent sends externally.".to_string(),
    }
}

fn agent_rule_id(title: &str) -> &'static str {
    let normalized = title.to_ascii_lowercase();
    if normalized.contains("unbounded") {
        "AGENT001"
    } else if normalized.contains("recursive") {
        "AGENT002"
    } else {
        "AGENT003"
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
    category: &Category,
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
                        category.clone(),
                        title,
                        severity,
                        id_allocator,
                    ));
                }
                collect_structured_permissions(
                    value,
                    relative_path,
                    contents,
                    category,
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
                    category,
                    id_allocator,
                    findings,
                );
            }
        }
        _ => {}
    }
}

fn collect_exfiltration(
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
                if key_is_external_destination(&normalized) && value_contains_external_url(value) {
                    let offset = find_case_insensitive(contents, key).unwrap_or_default();
                    findings.push(exfil_finding(
                        relative_path,
                        contents,
                        offset,
                        "External exfiltration endpoint configured",
                        "The AI configuration sends data to an explicit external URL, webhook, callback, or upload endpoint.",
                        id_allocator,
                    ));
                }

                if key_is_file_upload(&normalized) && value_is_enabled(value) {
                    let offset = find_case_insensitive(contents, key).unwrap_or_default();
                    findings.push(exfil_finding(
                        relative_path,
                        contents,
                        offset,
                        "Automatic file upload enabled",
                        "The AI configuration enables automatic file upload or export to an external destination.",
                        id_allocator,
                    ));
                }

                collect_exfiltration(value, relative_path, contents, id_allocator, findings);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_exfiltration(value, relative_path, contents, id_allocator, findings);
            }
        }
        _ => {}
    }
}

fn classify_permission(key: &str, value: &Value) -> Option<(&'static str, Severity)> {
    if matches!(
        key,
        "permissions" | "capabilities" | "allow" | "allowed_permissions"
    ) {
        if value_mentions_any(value, &["filesystem:*", "file_system:*", "fs:*"]) {
            return Some(("Unrestricted filesystem access", Severity::Critical));
        }

        if value_mentions_any(value, &["network:*", "internet:*", "http:*"]) {
            return Some(("Unrestricted network access", Severity::High));
        }

        if value_mentions_any(
            value,
            &[
                "shell",
                "command_execution",
                "code_execution",
                "sudo",
                "root",
            ],
        ) {
            return Some(("Privileged command execution", Severity::Critical));
        }

        if value_mentions_any(value, &["database:admin", "db:admin", "superuser"]) {
            return Some(("Database administrative access", Severity::High));
        }
    }

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

    if (key.contains("shell")
        || key.contains("command_execution")
        || key.contains("code_execution"))
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

fn permission_category(relative_path: &str, config: &AiConfigFile) -> Category {
    let path = relative_path.to_ascii_lowercase();
    if config.kind == AiConfigKind::Mcp || path.contains("mcp") {
        Category::McpSecurity
    } else {
        Category::AgentSecurity
    }
}

fn find_structured_autonomy(value: &Value) -> Option<(String, &'static str, Severity)> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let normalized = normalize_key(key);
                if matches!(
                    normalized.as_str(),
                    "max_iterations"
                        | "max_steps"
                        | "max_retries"
                        | "max_iter"
                        | "max_turns"
                        | "max_loops"
                        | "loop_limit"
                        | "recursion_limit"
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

                if normalized == "require_approval"
                    && value_matches_any(value, &["false", "disabled", "never", "none"])
                {
                    return Some((
                        key.clone(),
                        "Tool approval requirement disabled",
                        Severity::High,
                    ));
                }

                if normalized == "approval_policy"
                    && value_matches_any(value, &["never", "none", "disabled"])
                {
                    return Some((
                        key.clone(),
                        "Tool approval requirement disabled",
                        Severity::High,
                    ));
                }

                if normalized == "human_input_mode"
                    && value_matches_any(value, &["never", "none", "disabled"])
                {
                    return Some((
                        key.clone(),
                        "Human approval disabled for autonomous agent",
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

fn value_matches_any(value: &Value, matches: &[&str]) -> bool {
    value
        .as_str()
        .map(|text| {
            let normalized = normalize_key(text);
            matches
                .iter()
                .any(|candidate| normalized == normalize_key(candidate))
        })
        .unwrap_or(false)
}

fn key_is_external_destination(key: &str) -> bool {
    key.contains("webhook")
        || key.contains("callback_url")
        || key.contains("upload_url")
        || key.contains("external_url")
        || key.contains("destination_url")
        || key.contains("egress_url")
        || key.contains("export_url")
}

fn key_is_file_upload(key: &str) -> bool {
    matches!(
        key,
        "auto_upload"
            | "auto_upload_files"
            | "file_upload"
            | "file_uploads"
            | "upload_files"
            | "allow_uploads"
            | "allow_file_uploads"
            | "export_files"
            | "send_files"
    )
}

fn value_contains_external_url(value: &Value) -> bool {
    match value {
        Value::String(text) => is_external_http_url(text),
        Value::Array(values) => values.iter().any(value_contains_external_url),
        Value::Object(map) => map.values().any(value_contains_external_url),
        _ => false,
    }
}

fn is_external_http_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }

    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".local") {
        return false;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ip) => {
                !(ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified())
            }
            IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unspecified()),
        };
    }

    true
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
        let findings = analyze_mcp_file("agent.toml", "max_iterations = 0", &mut ids);

        assert!(findings.iter().any(|finding| finding.rule_id == "AGENT001"));
    }

    #[test]
    fn detects_auto_approval_agent_autonomy() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file("agent.toml", "auto_approve = true", &mut ids);

        assert!(findings.iter().any(|finding| finding.rule_id == "AGENT003"));
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

    #[test]
    fn detects_cursor_markdown_agent_rules() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            ".cursor/rules/agent.mdc",
            "```yaml\nallowed_tools:\n  - execute_shell\napproval_policy: never\n```\n",
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "MCP001"));
        assert!(findings.iter().any(|finding| finding.rule_id == "AGENT003"));
    }

    #[test]
    fn detects_framework_loop_controls() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "langgraph/langgraph.json",
            r#"{ "graphs": { "main": {} }, "recursion_limit": 0 }"#,
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "AGENT001"));

        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "crewai/crew.yaml",
            "agents:\n  - role: ops\n    max_iter: 0\n    tools: []\n",
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "AGENT001"));

        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "autogen/agent.json",
            r#"{ "human_input_mode": "NEVER", "code_execution_config": false }"#,
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "AGENT003"));
    }

    #[test]
    fn detects_external_exfiltration_endpoint() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "openai/agent.json",
            r#"{ "name": "ops", "model": "gpt-4.1", "tools": [], "webhook_url": "https://collector.example.com/hook" }"#,
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "EXFIL001"));
    }

    #[test]
    fn ignores_benign_local_exfiltration_urls() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "openai/agent.json",
            r#"{ "name": "ops", "model": "gpt-4.1", "tools": [], "webhook_url": "http://localhost:8787/hook" }"#,
            &mut ids,
        );

        assert!(!findings.iter().any(|finding| finding.rule_id == "EXFIL001"));
    }

    #[test]
    fn detects_permission_arrays() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_mcp_file(
            "agent.yaml",
            "permissions:\n  - filesystem:*\n  - shell\n",
            &mut ids,
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Unrestricted filesystem access")
        );
    }
}
