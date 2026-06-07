use anyhow::Result;
use sentinel_findings::ScanReport;
use tera::{Context, Tera};

const REPORT_TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel Security Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #586474;
      --border: #d9dee7;
      --critical: #9f1239;
      --high: #c2410c;
      --medium: #b45309;
      --low: #2563eb;
      --info: #475569;
    }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }
    main {
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    header {
      display: flex;
      justify-content: space-between;
      gap: 24px;
      align-items: flex-start;
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 24px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 30px;
      letter-spacing: 0;
    }
    h2 {
      font-size: 18px;
      margin: 28px 0 12px;
    }
    .muted {
      color: var(--muted);
    }
    .score {
      min-width: 150px;
      text-align: right;
      font-size: 14px;
      color: var(--muted);
    }
    .score strong {
      display: block;
      color: var(--text);
      font-size: 42px;
      line-height: 1;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
    }
    .metric, .finding {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
    }
    .metric span {
      display: block;
      color: var(--muted);
      font-size: 13px;
    }
    .metric strong {
      display: block;
      font-size: 24px;
      margin-top: 4px;
    }
    .finding {
      margin-bottom: 12px;
    }
    .finding-title {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin-bottom: 6px;
    }
    .finding-title strong {
      font-size: 16px;
    }
    .badge {
      border-radius: 999px;
      color: #fff;
      font-size: 12px;
      font-weight: 700;
      padding: 3px 8px;
      text-transform: uppercase;
    }
    .critical { background: var(--critical); }
    .high { background: var(--high); }
    .medium { background: var(--medium); }
    .low { background: var(--low); }
    .info { background: var(--info); }
    code {
      background: #edf1f7;
      border-radius: 4px;
      padding: 2px 4px;
      overflow-wrap: anywhere;
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Sentinel Security Report</h1>
        <div class="muted">Target <code>{{ report.summary.target }}</code></div>
        <div class="muted">Generated {{ report.summary.generated_at }}</div>
      </div>
      <div class="score">
        Security Score
        <strong>{{ report.summary.score }}/100</strong>
      </div>
    </header>

    <section class="metrics" aria-label="Scan summary">
      <div class="metric"><span>Files scanned</span><strong>{{ report.summary.scanned_files }}</strong></div>
      <div class="metric"><span>Total findings</span><strong>{{ report.summary.findings_count }}</strong></div>
      <div class="metric"><span>Critical</span><strong>{{ report.summary.severity_counts.critical }}</strong></div>
      <div class="metric"><span>High</span><strong>{{ report.summary.severity_counts.high }}</strong></div>
      <div class="metric"><span>Medium</span><strong>{{ report.summary.severity_counts.medium }}</strong></div>
      <div class="metric"><span>Low</span><strong>{{ report.summary.severity_counts.low }}</strong></div>
    </section>

    <section>
      <h2>Findings</h2>
      {% if report.findings | length == 0 %}
      <p class="muted">No findings were detected.</p>
      {% endif %}
      {% for finding in report.findings %}
      <article class="finding">
        <div class="finding-title">
          <span class="badge {{ finding.severity }}">{{ finding.severity }}</span>
          <strong>{{ finding.title }}</strong>
          <span class="muted">{{ finding.rule_id }} · {{ finding.confidence }} confidence</span>
        </div>
        <div class="muted"><code>{{ finding.location.path }}{% if finding.location.line %}:{{ finding.location.line }}{% endif %}</code></div>
        <p>{{ finding.description }}</p>
        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
      </article>
      {% endfor %}
    </section>
  </main>
</body>
</html>
"##;

pub fn render_html(report: &ScanReport) -> Result<String> {
    let mut context = Context::new();
    context.insert("report", report);
    Ok(Tera::one_off(REPORT_TEMPLATE, &context, true)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_empty_report() {
        let report = ScanReport::new(".", 0, Vec::new(), "0.1.3");
        let html = render_html(&report).unwrap();

        assert!(html.contains("Sentinel Security Report"));
        assert!(html.contains("No findings were detected."));
    }
}
