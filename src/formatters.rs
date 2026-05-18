use crate::scanner::{Finding, ScanResult};
use crate::target::TargetInfo;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report<'a> {
    pub scanned_at: DateTime<Utc>,
    pub root: &'a Path,
    pub target: &'a TargetInfo,
    pub summary: &'a crate::scanner::ScanSummary,
    pub skipped: &'a [crate::scanner::SkippedFile],
    pub findings: &'a [Finding],
}

pub fn format_report(format: OutputFormat, report: &Report<'_>) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        OutputFormat::Markdown => Ok(markdown_report(report)),
        OutputFormat::Text => Ok(text_report(report)),
    }
}

fn text_report(report: &Report<'_>) -> String {
    let mut out = String::new();
    out.push_str("Leak Hunter Report\n");
    out.push_str("==================\n\n");
    out.push_str(&format!("Target: {}\n", report.target.input));
    out.push_str(&format!("Root: {}\n", report.root.display()));
    out.push_str(&format!(
        "Summary: {} findings | {} scanned | {} skipped | min-risk {}\n",
        report.summary.findings,
        report.summary.files_scanned,
        report.summary.skipped,
        report.summary.min_risk
    ));
    out.push_str(&format!(
        "Redaction: {}\n\n",
        if report.summary.redact {
            "enabled; secrets are masked"
        } else {
            "DISABLED; raw secret values may be present"
        }
    ));

    if report.findings.is_empty() {
        out.push_str(&format!(
            "No findings at or above risk {}.\n",
            report.summary.min_risk
        ));
        return out;
    }

    for finding in report.findings {
        out.push_str(&format!(
            "[{}] {} ({})\n  Location: {}:{}:{}\n  Secret: {}\n  Hash: {}\n  Snippet: {}\n\n",
            risk_label(finding.risk_score),
            finding.title,
            finding.finding_type,
            finding.file_path,
            finding.line_number,
            finding.column_number,
            finding.secret,
            finding.secret_hash,
            finding.snippet
        ));
    }
    out
}

fn markdown_report(report: &Report<'_>) -> String {
    let mut out = String::new();
    out.push_str("# Leak Hunter Report\n\n");
    out.push_str("## Summary\n\n");
    out.push_str("| Field | Value |\n|---|---:|\n");
    out.push_str(&format!("| Findings | {} |\n", report.summary.findings));
    out.push_str(&format!(
        "| Files scanned | {} |\n",
        report.summary.files_scanned
    ));
    out.push_str(&format!("| Skipped | {} |\n", report.summary.skipped));
    out.push_str(&format!("| Minimum risk | {} |\n", report.summary.min_risk));
    out.push_str(&format!(
        "| Redaction | {} |\n\n",
        if report.summary.redact {
            "enabled; secrets are masked"
        } else {
            "**disabled; raw secret values may be present**"
        }
    ));

    let (critical, high, medium, low) = buckets(report.findings);
    out.push_str("## Risk Buckets\n\n| Bucket | Range | Count |\n|---|---:|---:|\n");
    out.push_str(&format!("| Critical | 90-100 | {critical} |\n"));
    out.push_str(&format!("| High | 75-89 | {high} |\n"));
    out.push_str(&format!("| Medium | 40-74 | {medium} |\n"));
    out.push_str(&format!("| Low | 0-39 | {low} |\n\n"));

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str(&format!(
            "No findings at or above risk {}.\n",
            report.summary.min_risk
        ));
        return out;
    }
    out.push_str("| Risk | Finding | Location | Secret | Snippet |\n|---:|---|---|---|---|\n");
    for finding in report.findings {
        out.push_str(&format!(
            "| {} | {} | `{}:{}:{}` | `{}` | `{}` |\n",
            finding.risk_score,
            escape_md(&finding.title),
            escape_md(&finding.file_path),
            finding.line_number,
            finding.column_number,
            escape_md(&finding.secret),
            escape_md(&finding.snippet)
        ));
    }
    out
}

fn buckets(findings: &[Finding]) -> (usize, usize, usize, usize) {
    findings.iter().fold((0, 0, 0, 0), |mut acc, finding| {
        match finding.risk_score {
            90..=100 => acc.0 += 1,
            75..=89 => acc.1 += 1,
            40..=74 => acc.2 += 1,
            _ => acc.3 += 1,
        }
        acc
    })
}

fn risk_label(score: u8) -> &'static str {
    match score {
        90..=100 => "Critical",
        75..=89 => "High",
        40..=74 => "Medium",
        _ => "Low",
    }
}

fn escape_md(value: &str) -> String {
    value.replace('|', "\\|").replace('`', "\\`")
}

pub fn report_from_scan<'a>(
    scanned_at: DateTime<Utc>,
    root: &'a Path,
    target: &'a TargetInfo,
    scan: &'a ScanResult,
) -> Report<'a> {
    Report {
        scanned_at,
        root,
        target,
        summary: &scan.summary,
        skipped: &scan.skipped,
        findings: &scan.findings,
    }
}
