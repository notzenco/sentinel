use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use sentinel_common::ScanProfile;
use sentinel_findings::{ScanReport, Severity};
use sentinel_html_report::render_html;
use sentinel_sarif::to_sarif_string;
use sentinel_scanner::{ScanOptions, Scanner, SentinelConfig};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Parser)]
#[command(name = "sentinel")]
#[command(about = "Offline-first AI security scanner")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan a repository, prompt directory, MCP server, or agent project.
    Scan(ScanArgs),
    /// Run Sentinel in CI mode and fail on high severity findings by default.
    Ci(CiArgs),
    /// Scan Claude Code project files and MCP definitions.
    Claude(ProfileArgs),
    /// Scan Cursor project rules, agents, and prompts.
    Cursor(ProfileArgs),
}

#[derive(Debug, Args, Clone)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long, conflicts_with_all = ["sarif", "html"])]
    json: bool,
    #[arg(long, conflicts_with_all = ["json", "html"])]
    sarif: bool,
    #[arg(long, conflicts_with_all = ["json", "sarif"])]
    html: bool,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_parser = parse_severity)]
    fail_on: Option<Severity>,
}

#[derive(Debug, Args, Clone)]
struct CiArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_parser = parse_severity, default_value = "high")]
    fail_on: Severity,
    #[arg(long)]
    sarif_output: Option<PathBuf>,
}

#[derive(Debug, Args, Clone)]
struct ProfileArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long, conflicts_with_all = ["sarif", "html"])]
    json: bool,
    #[arg(long, conflicts_with_all = ["json", "html"])]
    sarif: bool,
    #[arg(long, conflicts_with_all = ["json", "sarif"])]
    html: bool,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_parser = parse_severity)]
    fail_on: Option<Severity>,
}

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{} {error:#}", "error:".red().bold());
            2
        }
    };
    std::process::exit(exit_code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Ci(args) => run_ci(args),
        Commands::Claude(args) => run_profile(args, ScanProfile::Claude),
        Commands::Cursor(args) => run_profile(args, ScanProfile::Cursor),
    }
}

fn run_scan(args: ScanArgs) -> Result<i32> {
    let report = execute_scan(&args.path, ScanProfile::General, args.config.as_ref())?;
    emit_report(
        &report,
        args.json,
        args.sarif,
        args.html,
        args.output.as_ref(),
    )?;
    Ok(exit_for_threshold(&report, args.fail_on))
}

fn run_profile(args: ProfileArgs, profile: ScanProfile) -> Result<i32> {
    let report = execute_scan(&args.path, profile, args.config.as_ref())?;
    emit_report(
        &report,
        args.json,
        args.sarif,
        args.html,
        args.output.as_ref(),
    )?;
    Ok(exit_for_threshold(&report, args.fail_on))
}

fn run_ci(args: CiArgs) -> Result<i32> {
    let report = execute_scan(&args.path, ScanProfile::General, args.config.as_ref())?;
    print_terminal_report(&report);

    if let Some(path) = args.sarif_output.as_ref() {
        write_file(path, &to_sarif_string(&report)?)?;
    }

    Ok(if report.has_findings_at_or_above(args.fail_on) {
        1
    } else {
        0
    })
}

fn execute_scan(
    target: &PathBuf,
    profile: ScanProfile,
    config_path: Option<&PathBuf>,
) -> Result<ScanReport> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    spinner.set_message("scanning");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let (config, loaded_config_path) = load_config(target, config_path)?;
    let mut options = ScanOptions::new(target);
    options.profile = profile;
    options.rules_dir = config
        .rules_dir
        .map(|path| resolve_config_relative_path(&path, loaded_config_path.as_deref()))
        .or_else(default_rules_dir);
    options.exclude = config.exclude;
    options.max_file_bytes = config.max_file_bytes;

    let report = Scanner::new(options).scan();
    spinner.finish_and_clear();
    report
}

fn load_config(target: &Path, path: Option<&PathBuf>) -> Result<(SentinelConfig, Option<PathBuf>)> {
    let path = path.cloned().or_else(|| default_config_path(target));
    let Some(path) = path else {
        return Ok((
            SentinelConfig {
                rules_dir: None,
                exclude: Vec::new(),
                max_file_bytes: None,
            },
            None,
        ));
    };

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let config: SentinelConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse config {}", path.display()))?;
    config
        .validate(path.parent())
        .with_context(|| format!("invalid config {}", path.display()))?;
    Ok((config, Some(path)))
}

fn default_rules_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_rules = manifest_dir
        .parent()
        .and_then(|apps| apps.parent())
        .map(|root| root.join("rules"));

    if let Some(path) = workspace_rules {
        if path.exists() {
            return Some(path);
        }
    }

    let cwd_rules = std::env::current_dir().ok()?.join("rules");
    cwd_rules.exists().then_some(cwd_rules)
}

fn default_config_path(target: &Path) -> Option<PathBuf> {
    let cwd_config = std::env::current_dir().ok()?.join("sentinel.yml");
    if cwd_config.exists() {
        return Some(cwd_config);
    }

    let target_config = target.join("sentinel.yml");
    target_config.exists().then_some(target_config)
}

fn resolve_config_relative_path(path: &Path, config_path: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    config_path
        .and_then(Path::parent)
        .map(|parent| parent.join(path))
        .unwrap_or_else(|| path.to_path_buf())
}

fn emit_report(
    report: &ScanReport,
    json: bool,
    sarif: bool,
    html: bool,
    output: Option<&PathBuf>,
) -> Result<()> {
    if json {
        let body = serde_json::to_string_pretty(report)?;
        return emit_text(&body, output);
    }

    if sarif {
        let body = to_sarif_string(report)?;
        return emit_text(&body, output);
    }

    if html {
        let body = render_html(report)?;
        let path = output
            .cloned()
            .unwrap_or_else(|| PathBuf::from("report.html"));
        return write_file(&path, &body);
    }

    print_terminal_report(report);
    Ok(())
}

fn emit_text(body: &str, output: Option<&PathBuf>) -> Result<()> {
    if let Some(path) = output {
        write_file(path, body)
    } else {
        println!("{body}");
        Ok(())
    }
}

fn write_file(path: &PathBuf, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }
    }
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))
}

fn print_terminal_report(report: &ScanReport) {
    let summary = &report.summary;
    println!("{}", "Sentinel Security Scan".bold());
    println!("Target: {}", summary.target);
    println!("Files scanned: {}", summary.scanned_files);
    println!("Security Score: {}/100", color_score(summary.score));
    println!(
        "Findings: {} critical, {} high, {} medium, {} low, {} info",
        color_count(summary.severity_counts.critical, Severity::Critical),
        color_count(summary.severity_counts.high, Severity::High),
        color_count(summary.severity_counts.medium, Severity::Medium),
        color_count(summary.severity_counts.low, Severity::Low),
        color_count(summary.severity_counts.info, Severity::Info),
    );

    if report.findings.is_empty() {
        println!();
        println!("{}", "No findings detected.".green());
        return;
    }

    println!();
    println!(
        "{:<11} {:<10} {:<12} {:<28} Location",
        "Severity", "Confidence", "Rule", "Title"
    );
    println!("{}", "-".repeat(96));

    for finding in &report.findings {
        let location = match finding.location.line {
            Some(line) => format!("{}:{line}", finding.location.path),
            None => finding.location.path.clone(),
        };
        println!(
            "{:<11} {:<10} {:<12} {:<28} {}",
            severity_label(finding.severity),
            finding.confidence.to_string(),
            finding.rule_id,
            truncate(&finding.title, 28),
            location
        );
    }
}

fn color_score(score: u8) -> colored::ColoredString {
    let value = score.to_string();
    match score {
        90..=100 => value.green().bold(),
        70..=89 => value.yellow().bold(),
        _ => value.red().bold(),
    }
}

fn color_count(count: usize, severity: Severity) -> colored::ColoredString {
    let value = count.to_string();
    match severity {
        Severity::Critical | Severity::High if count > 0 => value.red().bold(),
        Severity::Medium if count > 0 => value.yellow().bold(),
        Severity::Low if count > 0 => value.blue().bold(),
        Severity::Info if count > 0 => value.normal(),
        _ => value.dimmed(),
    }
}

fn severity_label(severity: Severity) -> colored::ColoredString {
    let label = severity.to_string();
    match severity {
        Severity::Critical => label.red().bold(),
        Severity::High => label.red(),
        Severity::Medium => label.yellow(),
        Severity::Low => label.blue(),
        Severity::Info => label.normal(),
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_chars {
        return value.to_string();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn exit_for_threshold(report: &ScanReport, threshold: Option<Severity>) -> i32 {
    if threshold
        .map(|severity| report.has_findings_at_or_above(severity))
        .unwrap_or(false)
    {
        1
    } else {
        0
    }
}

fn parse_severity(value: &str) -> Result<Severity, String> {
    Severity::from_str(value)
        .map_err(|_| "expected one of: critical, high, medium, low, info".to_string())
}
