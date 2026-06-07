use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ORDERED: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 7,
            Severity::High => 15,
            Severity::Critical => 25,
        }
    }

    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }

    pub fn is_at_least(self, threshold: Severity) -> bool {
        self >= threshold
    }
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(value)
    }
}

impl FromStr for Severity {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(ParseEnumError::new("severity", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn multiplier(self) -> f32 {
        match self {
            Confidence::Low => 0.5,
            Confidence::Medium => 0.75,
            Confidence::High => 1.0,
        }
    }
}

impl Display for Confidence {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        };
        f.write_str(value)
    }
}

impl FromStr for Confidence {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Ok(Confidence::Low),
            "medium" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            _ => Err(ParseEnumError::new("confidence", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    PromptInjection,
    SecretLeakage,
    Jailbreak,
    McpSecurity,
    AgentSecurity,
    DataExfiltration,
    WorkflowSecurity,
    SupplyChain,
    Configuration,
}

impl Display for Category {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Category::PromptInjection => "prompt_injection",
            Category::SecretLeakage => "secret_leakage",
            Category::Jailbreak => "jailbreak",
            Category::McpSecurity => "mcp_security",
            Category::AgentSecurity => "agent_security",
            Category::DataExfiltration => "data_exfiltration",
            Category::WorkflowSecurity => "workflow_security",
            Category::SupplyChain => "supply_chain",
            Category::Configuration => "configuration",
        };
        f.write_str(value)
    }
}

impl FromStr for Category {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "prompt_injection" => Ok(Category::PromptInjection),
            "secret_leakage" | "secrets" => Ok(Category::SecretLeakage),
            "jailbreak" => Ok(Category::Jailbreak),
            "mcp_security" | "mcp" => Ok(Category::McpSecurity),
            "agent_security" | "agents" => Ok(Category::AgentSecurity),
            "data_exfiltration" => Ok(Category::DataExfiltration),
            "workflow_security" | "workflows" => Ok(Category::WorkflowSecurity),
            "supply_chain" => Ok(Category::SupplyChain),
            "configuration" | "config" => Ok(Category::Configuration),
            _ => Err(ParseEnumError::new("category", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

impl Location {
    pub fn new(path: impl Into<String>, line: Option<usize>, column: Option<usize>) -> Self {
        Self {
            path: path.into(),
            line,
            column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: Category,
    pub location: Location,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
            }
        }
        counts
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub target: String,
    pub scanned_files: usize,
    pub findings_count: usize,
    pub severity_counts: SeverityCounts,
    pub score: u8,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn new(
        target: impl Into<String>,
        scanned_files: usize,
        mut findings: Vec<Finding>,
        version: impl Into<String>,
    ) -> Self {
        findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.location.path.cmp(&right.location.path))
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });

        let severity_counts = SeverityCounts::from_findings(&findings);
        let score = calculate_score(&findings);
        let findings_count = findings.len();

        Self {
            tool: "sentinel".to_string(),
            version: version.into(),
            summary: ScanSummary {
                target: target.into(),
                scanned_files,
                findings_count,
                severity_counts,
                score,
                generated_at: Utc::now(),
            },
            findings,
        }
    }

    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity.is_at_least(threshold))
    }

    pub fn by_category(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.category.to_string()).or_insert(0) += 1;
        }
        counts
    }
}

pub fn calculate_score(findings: &[Finding]) -> u8 {
    let penalty = findings
        .iter()
        .map(|finding| finding.severity.weight() as f32 * finding.confidence.multiplier())
        .sum::<f32>()
        .round() as i32;

    (100 - penalty).clamp(0, 100) as u8
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid {kind}: {value}")]
pub struct ParseEnumError {
    kind: &'static str,
    value: String,
}

impl ParseEnumError {
    fn new(kind: &'static str, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            id: "SENT-0001".to_string(),
            rule_id: "TEST001".to_string(),
            title: "test".to_string(),
            description: "test".to_string(),
            severity,
            confidence,
            category: Category::Configuration,
            location: Location::new("file.txt", Some(1), Some(1)),
            recommendation: "fix it".to_string(),
        }
    }

    #[test]
    fn severity_order_matches_fail_thresholds() {
        assert!(Severity::Critical.is_at_least(Severity::High));
        assert!(Severity::High.is_at_least(Severity::Medium));
        assert!(!Severity::Low.is_at_least(Severity::High));
    }

    #[test]
    fn score_penalizes_severity_and_confidence() {
        let high = finding(Severity::High, Confidence::High);
        let low = finding(Severity::Low, Confidence::Low);

        assert!(calculate_score(&[high]) < calculate_score(&[low]));
    }

    #[test]
    fn report_counts_findings() {
        let report = ScanReport::new(
            ".",
            2,
            vec![
                finding(Severity::Critical, Confidence::High),
                finding(Severity::Medium, Confidence::Medium),
            ],
            "0.1.1",
        );

        assert_eq!(report.summary.findings_count, 2);
        assert_eq!(report.summary.severity_counts.critical, 1);
        assert_eq!(report.summary.severity_counts.medium, 1);
        assert!(report.has_findings_at_or_above(Severity::High));
    }
}
