use regex::Regex;
use sentinel_common::line_col_for_offset;
use sentinel_findings::{Category, Confidence, Finding, Location, Severity};
use sentinel_rules::FindingIdAllocator;

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
    findings.extend(detect_dangerous_tools(
        relative_path,
        contents,
        id_allocator,
    ));
    findings.extend(detect_permissions(relative_path, contents, id_allocator));
    findings.extend(detect_agent_autonomy(relative_path, contents, id_allocator));
    findings
}

fn detect_dangerous_tools(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for tool in DANGEROUS_TOOL_NAMES {
        let regex = Regex::new(&format!(
            r#"(?i)["']?(name|tool|function_name|command)["']?\s*[:=]\s*["']?{}\b["']?"#,
            regex::escape(tool)
        ))
        .expect("dangerous tool regex must compile");

        if let Some(matched) = regex.find(contents) {
            let (line, column) = line_col_for_offset(contents, matched.start());
            findings.push(Finding {
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
            });
        }
    }
    findings
}

fn detect_permissions(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (pattern, title, severity) in PERMISSION_PATTERNS {
        let regex = Regex::new(pattern).expect("permission regex must compile");
        if let Some(matched) = regex.find(contents) {
            let (line, column) = line_col_for_offset(contents, matched.start());
            findings.push(Finding {
                id: id_allocator.next_id(),
                rule_id: "MCP002".to_string(),
                title: (*title).to_string(),
                description: "The MCP or agent configuration grants broad access that can amplify prompt injection or tool abuse.".to_string(),
                severity: *severity,
                confidence: Confidence::Medium,
                category: Category::McpSecurity,
                location: Location::new(relative_path, Some(line), Some(column)),
                recommendation: "Scope permissions to explicit paths, hosts, commands, and database operations needed by the application.".to_string(),
            });
        }
    }
    findings
}

fn detect_agent_autonomy(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let patterns = [
        r"(?i)(max_iterations|max_steps|max_retries)\s*[:=]\s*(-1|0|null|unlimited)",
        r"(?i)(recursive|self_call|self-calling)\s*[:=]\s*(true|enabled|allow)",
        r"(?i)(auto_approve|auto-approve|require_approval)\s*[:=]\s*(true|false)",
    ];

    let mut findings = Vec::new();
    for pattern in patterns {
        let regex = Regex::new(pattern).expect("autonomy regex must compile");
        if let Some(matched) = regex.find(contents) {
            let (line, column) = line_col_for_offset(contents, matched.start());
            findings.push(Finding {
                id: id_allocator.next_id(),
                rule_id: "AGENT001".to_string(),
                title: "Unbounded or unsafe agent autonomy".to_string(),
                description: "The agent configuration may allow unbounded execution, recursive calls, or automatic approval.".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: Category::AgentSecurity,
                location: Location::new(relative_path, Some(line), Some(column)),
                recommendation: "Set explicit execution limits, disable recursive self-calls, and require approval for sensitive tools.".to_string(),
            });
            break;
        }
    }
    findings
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
}
