use once_cell::sync::Lazy;
use regex::Regex;
use sentinel_common::line_col_for_offset;
use sentinel_findings::{Category, Confidence, Finding, Location, Severity};
use sentinel_rules::FindingIdAllocator;
use std::collections::HashMap;

#[derive(Debug)]
struct SecretPattern {
    rule_id: &'static str,
    title: &'static str,
    description: &'static str,
    regex: Regex,
    severity: Severity,
    confidence: Confidence,
}

static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    vec![
        SecretPattern {
            rule_id: "SEC001",
            title: "OpenAI API key",
            description: "An OpenAI API key-like token was found in source-controlled text.",
            regex: Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b").unwrap(),
            severity: Severity::Critical,
            confidence: Confidence::High,
        },
        SecretPattern {
            rule_id: "SEC002",
            title: "Anthropic API key",
            description: "An Anthropic API key-like token was found in source-controlled text.",
            regex: Regex::new(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b").unwrap(),
            severity: Severity::Critical,
            confidence: Confidence::High,
        },
        SecretPattern {
            rule_id: "SEC003",
            title: "GitHub token",
            description: "A GitHub token-like value was found in source-controlled text.",
            regex: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b").unwrap(),
            severity: Severity::Critical,
            confidence: Confidence::High,
        },
        SecretPattern {
            rule_id: "SEC004",
            title: "AWS access key id",
            description: "An AWS access key id was found in source-controlled text.",
            regex: Regex::new(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b").unwrap(),
            severity: Severity::High,
            confidence: Confidence::High,
        },
        SecretPattern {
            rule_id: "SEC005",
            title: "Database connection URL",
            description: "A database URL with inline credentials was found in source-controlled text.",
            regex: Regex::new(
                r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+",
            )
            .unwrap(),
            severity: Severity::Critical,
            confidence: Confidence::High,
        },
        SecretPattern {
            rule_id: "SEC006",
            title: "JWT token",
            description: "A JWT-like token was found in source-controlled text.",
            regex: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                .unwrap(),
            severity: Severity::High,
            confidence: Confidence::Medium,
        },
        SecretPattern {
            rule_id: "SEC007",
            title: "Azure storage connection string",
            description: "An Azure storage connection string was found in source-controlled text.",
            regex: Regex::new(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}")
                .unwrap(),
            severity: Severity::Critical,
            confidence: Confidence::High,
        },
    ]
});

static ASSIGNMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b[A-Za-z0-9_-]*(api[_-]?key|secret|token|password|private[_-]?key)[A-Za-z0-9_-]*\b\s*[:=]\s*['"]?([A-Za-z0-9_/\-+=.]{24,})['"]?"#,
    )
    .unwrap()
});

pub fn analyze_secret_file(
    relative_path: &str,
    contents: &str,
    id_allocator: &mut FindingIdAllocator,
) -> Vec<Finding> {
    if should_skip_secret_path(relative_path) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut found_specific_secret = false;
    for pattern in SECRET_PATTERNS.iter() {
        if let Some(matched) = pattern.regex.find(contents) {
            found_specific_secret = true;
            let (line, column) = line_col_for_offset(contents, matched.start());
            findings.push(Finding {
                id: id_allocator.next_id(),
                rule_id: pattern.rule_id.to_string(),
                title: pattern.title.to_string(),
                description: pattern.description.to_string(),
                severity: pattern.severity,
                confidence: pattern.confidence,
                category: Category::SecretLeakage,
                location: Location::new(relative_path, Some(line), Some(column)),
                recommendation: "Revoke the credential, remove it from the repository, and load secrets from a managed secret store.".to_string(),
            });
        }
    }

    if !found_specific_secret {
        if let Some(captures) = ASSIGNMENT_PATTERN.captures(contents) {
            let Some(secret_value) = captures.get(2) else {
                return findings;
            };
            let value = secret_value.as_str();
            if shannon_entropy(value) >= 4.0 && unique_character_count(value) >= 12 {
                let (line, column) = line_col_for_offset(contents, secret_value.start());
                findings.push(Finding {
                    id: id_allocator.next_id(),
                    rule_id: "SEC100".to_string(),
                    title: "High entropy secret-like assignment".to_string(),
                    description: "A high entropy value assigned to a sensitive variable name was found.".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    category: Category::SecretLeakage,
                    location: Location::new(relative_path, Some(line), Some(column)),
                    recommendation: "Move sensitive values to a secret manager and replace committed values with references.".to_string(),
                });
            }
        }
    }

    findings
}

pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = HashMap::new();
    for byte in value.bytes() {
        *counts.entry(byte).or_insert(0usize) += 1;
    }

    let length = value.len() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn unique_character_count(value: &str) -> usize {
    let mut chars = value.chars().collect::<Vec<_>>();
    chars.sort_unstable();
    chars.dedup();
    chars.len()
}

fn should_skip_secret_path(relative_path: &str) -> bool {
    let path = relative_path.to_ascii_lowercase();
    path.contains("cargo.lock")
        || path.contains("package-lock.json")
        || path.contains("pnpm-lock.yaml")
        || path.contains("yarn.lock")
        || path.contains("target/")
        || path.contains("node_modules/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openai_key_without_leaking_value() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_secret_file(
            ".env",
            // sentinel:ignore SEC001 test credential fixture
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
            &mut ids,
        );

        assert_eq!(findings.len(), 1);
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456"));
    }

    #[test]
    fn entropy_distinguishes_random_like_values() {
        assert!(shannon_entropy("abcdefghijklmnopqrstuvwxyz1234567890+/=") > 4.0);
        assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaa") < 1.0);
    }

    #[test]
    fn detects_high_entropy_secret_assignment() {
        let mut ids = FindingIdAllocator::new();
        let findings = analyze_secret_file(
            "config.yml",
            "jwt_secret: Ab9kL2qP0xY7vN3sT8mQ1zR6cW4eU5",
            &mut ids,
        );

        assert!(findings.iter().any(|finding| finding.rule_id == "SEC100"));
    }
}
