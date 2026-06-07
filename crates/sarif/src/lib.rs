use anyhow::Result;
use sentinel_findings::{Finding, ScanReport};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn to_sarif(report: &ScanReport) -> Value {
    let rules = unique_rules(&report.findings)
        .into_values()
        .map(|finding| {
            json!({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.description
                },
                "help": {
                    "text": finding.recommendation
                },
                "properties": {
                    "category": finding.category.to_string(),
                    "severity": finding.severity.to_string(),
                    "confidence": finding.confidence.to_string()
                }
            })
        })
        .collect::<Vec<_>>();

    let results = report
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.rule_id,
                "level": finding.severity.sarif_level(),
                "message": {
                    "text": format!("{}: {}", finding.title, finding.description)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.path
                        },
                        "region": {
                            "startLine": finding.location.line.unwrap_or(1),
                            "startColumn": finding.location.column.unwrap_or(1)
                        }
                    }
                }],
                "properties": {
                    "sentinelId": finding.id,
                    "severity": finding.severity.to_string(),
                    "confidence": finding.confidence.to_string(),
                    "recommendation": finding.recommendation
                }
            })
        })
        .collect::<Vec<_>>();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sentinel",
                    "informationUri": "https://github.com/notzenco/sentinel",
                    "semanticVersion": report.version,
                    "rules": rules
                }
            },
            "results": results,
            "properties": {
                "securityScore": report.summary.score,
                "scannedFiles": report.summary.scanned_files,
                "findingsCount": report.summary.findings_count
            }
        }]
    })
}

pub fn to_sarif_string(report: &ScanReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(&to_sarif(report))?)
}

fn unique_rules(findings: &[Finding]) -> BTreeMap<String, Finding> {
    let mut rules = BTreeMap::new();
    for finding in findings {
        rules
            .entry(finding.rule_id.clone())
            .or_insert_with(|| finding.clone());
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_findings::{Category, Confidence, Location, Severity};

    #[test]
    fn maps_findings_to_sarif_results() {
        let report = ScanReport::new(
            ".",
            1,
            vec![Finding {
                id: "SENT-0001".to_string(),
                rule_id: "PROMPT001".to_string(),
                title: "Prompt override".to_string(),
                description: "Detected override.".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: Category::PromptInjection,
                location: Location::new("prompt.md", Some(1), Some(1)),
                recommendation: "Remove it.".to_string(),
            }],
            "0.1.1",
        );

        let sarif = to_sarif(&report);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "PROMPT001");
    }
}
