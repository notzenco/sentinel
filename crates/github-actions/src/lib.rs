use regex::Regex;
use sentinel_common::line_col_for_offset;
use sentinel_findings::{Category, Confidence, Finding, Location, Severity};
use sentinel_rules::FindingIdAllocator;

pub fn analyze_workflow_file(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    if !is_workflow_path(relative_path) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    findings.extend(check_pull_request_target(
        relative_path,
        contents,
        id_allocator,
    ));
    findings.extend(check_write_all_permissions(
        relative_path,
        contents,
        id_allocator,
    ));
    findings.extend(check_curl_pipe_shell(relative_path, contents, id_allocator));
    findings.extend(check_unpinned_actions(
        relative_path,
        contents,
        id_allocator,
    ));
    findings
}

fn check_pull_request_target(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let trigger = Regex::new(r"(?im)^\s*pull_request_target\s*:").unwrap();
    if let Some(matched) = trigger.find(contents) {
        let (line, column) = line_col_for_offset(contents, matched.start());
        return vec![Finding {
            id: id_allocator.next_id(),
            rule_id: "GHA001".to_string(),
            title: "pull_request_target workflow trigger".to_string(),
            description: "The workflow uses pull_request_target, which runs with elevated token permissions against untrusted pull request content.".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: Category::WorkflowSecurity,
            location: Location::new(relative_path, Some(line), Some(column)),
            recommendation: "Use pull_request where possible, or isolate checkout and script execution from untrusted pull request code.".to_string(),
        }];
    }
    Vec::new()
}

fn check_write_all_permissions(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let pattern = Regex::new(r"(?im)^\s*permissions\s*:\s*write-all\s*$").unwrap();
    if let Some(matched) = pattern.find(contents) {
        let (line, column) = line_col_for_offset(contents, matched.start());
        return vec![Finding {
            id: id_allocator.next_id(),
            rule_id: "GHA002".to_string(),
            title: "Workflow grants write-all permissions".to_string(),
            description: "The workflow grants broad write permissions to the GitHub token."
                .to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: Category::WorkflowSecurity,
            location: Location::new(relative_path, Some(line), Some(column)),
            recommendation: "Set the minimum required token permissions explicitly for each job."
                .to_string(),
        }];
    }
    Vec::new()
}

fn check_curl_pipe_shell(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let pattern = Regex::new(r"(?i)(curl|wget).{0,120}(\|\s*(sh|bash|pwsh|powershell))").unwrap();
    if let Some(matched) = pattern.find(contents) {
        let (line, column) = line_col_for_offset(contents, matched.start());
        return vec![Finding {
            id: id_allocator.next_id(),
            rule_id: "GHA003".to_string(),
            title: "Workflow pipes remote script into shell".to_string(),
            description:
                "The workflow downloads remote content and executes it directly in a shell."
                    .to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            category: Category::SupplyChain,
            location: Location::new(relative_path, Some(line), Some(column)),
            recommendation:
                "Pin downloads by checksum, vendor trusted scripts, or use pinned actions instead."
                    .to_string(),
        }];
    }
    Vec::new()
}

fn check_unpinned_actions(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    let pattern = Regex::new(
        r"(?im)^\s*uses\s*:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(v\d+|main|master|latest)\s*$",
    )
    .unwrap();
    if let Some(matched) = pattern.find(contents) {
        let (line, column) = line_col_for_offset(contents, matched.start());
        return vec![Finding {
            id: id_allocator.next_id(),
            rule_id: "GHA004".to_string(),
            title: "Workflow action is not pinned to a commit".to_string(),
            description: "The workflow references an action by a mutable branch or version tag instead of a commit SHA.".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: Category::SupplyChain,
            location: Location::new(relative_path, Some(line), Some(column)),
            recommendation: "Pin third-party actions to a full commit SHA and review updates deliberately.".to_string(),
        }];
    }
    Vec::new()
}

fn is_workflow_path(relative_path: &str) -> bool {
    let path = relative_path.to_ascii_lowercase();
    path.starts_with(".github/workflows/") && (path.ends_with(".yml") || path.ends_with(".yaml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pull_request_target() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_workflow_file(
            ".github/workflows/ci.yml",
            "on:\n  pull_request_target:\npermissions: write-all\n",
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "GHA001"));
        assert!(findings.iter().any(|finding| finding.rule_id == "GHA002"));
    }
}
