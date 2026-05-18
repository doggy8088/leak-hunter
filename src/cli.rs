use crate::formatters::{format_report, report_from_scan, OutputFormat};
use crate::scanner::{scan_path, ScanOptions};
use crate::target::{resolve_target, TargetOptions};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "leak-hunter",
    version,
    about = "Scan local paths or GitHub repositories for likely leaked secrets."
)]
pub struct Cli {
    /// local path, GitHub URL, or owner/repo shorthand
    #[arg(default_value = ".")]
    pub target: String,

    /// include glob; repeatable
    #[arg(short = 'i', long = "include")]
    pub include: Vec<String>,

    /// exclude glob; repeatable
    #[arg(short = 'x', long = "exclude")]
    pub exclude: Vec<String>,

    /// disable built-in excludes such as .git, node_modules, and build outputs
    #[arg(long = "no-default-exclude", default_value_t = false)]
    pub no_default_exclude: bool,

    /// output format
    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// output JSON report for tool integrations
    #[arg(long = "json", default_value_t = false)]
    pub json: bool,

    /// write report to a file instead of stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// minimum risk score to report (0-100)
    #[arg(long = "min-risk", default_value_t = 40)]
    pub min_risk: u8,

    /// maximum file size to scan in MiB
    #[arg(long = "max-file-size-mb", default_value_t = 5)]
    pub max_file_size_mb: u64,

    /// number of files to scan concurrently
    #[arg(short = 'c', long = "concurrency", default_value_t = default_concurrency())]
    pub concurrency: usize,

    /// redact secret values in reports
    #[arg(long = "redact", default_value_t = true, conflicts_with = "no_redact")]
    pub redact: bool,

    /// include raw secret values in reports; use with care
    #[arg(long = "no-redact", default_value_t = false)]
    pub no_redact: bool,

    /// keep temporary clones for GitHub targets instead of cleaning them up
    #[arg(long = "keep-temp", default_value_t = false)]
    pub keep_temp: bool,

    /// directory for temporary GitHub clones
    #[arg(long = "cache-dir")]
    pub cache_dir: Option<PathBuf>,

    /// branch or tag to clone for GitHub targets
    #[arg(long = "branch")]
    pub branch: Option<String>,

    /// print debug details about scan decisions to stderr
    #[arg(long = "debug", default_value_t = false)]
    pub debug: bool,
}

pub fn run(cli: Cli) -> Result<i32> {
    validate(&cli)?;
    let format = if cli.json {
        OutputFormat::Json
    } else {
        cli.format
    };
    let redact = !cli.no_redact;

    if cli.debug {
        eprintln!("start scan");
    }

    let mut target = resolve_target(
        &cli.target,
        &TargetOptions {
            keep_temp: cli.keep_temp,
            cache_dir: cli.cache_dir.clone(),
            branch: cli.branch.clone(),
        },
    )?;

    let scan_options = ScanOptions {
        include: cli.include,
        exclude: cli.exclude,
        default_exclude: !cli.no_default_exclude,
        min_risk: cli.min_risk,
        max_file_size_bytes: cli.max_file_size_mb * 1024 * 1024,
        concurrency: cli.concurrency,
        redact,
        debug: cli.debug,
    };

    let scan = scan_path(&target.info.path, &scan_options)?;

    if cli.debug {
        eprintln!("cleanup temporary target if required");
    }
    target.cleanup();

    let report = report_from_scan(Utc::now(), &target.info.path, &target.info, &scan);
    let output = format_report(format, &report)?;

    if let Some(path) = cli.output {
        std::fs::write(&path, output)
            .with_context(|| format!("failed to write {}", path.display()))?;
        if !redact {
            eprintln!("Warning: report was written with redaction disabled.");
        }
    } else {
        println!("{output}");
        if !redact && format == OutputFormat::Json {
            eprintln!(
                "Warning: JSON output includes raw secret values because --no-redact was used."
            );
        }
    }

    Ok(if scan.summary.findings > 0 { 1 } else { 0 })
}

fn validate(cli: &Cli) -> Result<()> {
    if cli.min_risk > 100 {
        bail!("min-risk must be between 0 and 100");
    }
    if cli.max_file_size_mb == 0 {
        bail!("max-file-size-mb must be greater than 0");
    }
    if cli.concurrency == 0 {
        bail!("concurrency must be at least 1");
    }
    Ok(())
}

fn default_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
