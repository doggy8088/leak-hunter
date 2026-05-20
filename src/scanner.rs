use crate::patterns::{is_likely_placeholder, SECRET_PATTERNS};
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub default_exclude: bool,
    pub min_risk: u8,
    pub max_file_size_bytes: u64,
    pub concurrency: usize,
    pub redact: bool,
    pub debug: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub files_enumerated: usize,
    pub files_scanned: usize,
    pub findings: usize,
    pub skipped: usize,
    pub skipped_binary: usize,
    pub skipped_too_large: usize,
    pub skipped_unreadable: usize,
    pub concurrency: usize,
    pub max_file_size_bytes: u64,
    pub min_risk: u8,
    pub redact: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(rename = "type")]
    pub finding_type: String,
    pub title: String,
    pub file_path: String,
    pub line_number: usize,
    pub column_number: usize,
    pub risk_score: u8,
    pub entropy: f64,
    pub secret_hash: String,
    pub secret: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedFile {
    pub file_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
}

struct FileOutcome {
    scanned: bool,
    skipped: Option<SkippedFile>,
    findings: Vec<Finding>,
}

const DEFAULT_EXCLUDES: &[&str] = &[
    "**/.git/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/coverage/**",
    "**/.next/**",
    "**/.nuxt/**",
    "**/.cache/**",
    "**/.leak-hunter-cache/**",
    "**/vendor/**",
    "target/**",
    "**/target/**",
];

pub fn scan_path(root: &Path, options: &ScanOptions) -> Result<ScanResult> {
    let include = build_globset(&options.include)?;
    let mut excludes = options.exclude.clone();
    if options.default_exclude {
        excludes.extend(DEFAULT_EXCLUDES.iter().map(|s| s.to_string()));
    }
    let exclude = build_globset(&excludes)?;

    if options.debug {
        eprintln!(
            "scan options: include={:?} exclude={:?} min_risk={} redact={}",
            options.include, excludes, options.min_risk, options.redact
        );
    }

    let files: Vec<PathBuf> = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(options.default_exclude)
        .git_exclude(options.default_exclude)
        .parents(options.default_exclude)
        .build()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .filter_map(|entry| {
            let path = entry.into_path();
            let rel = path.strip_prefix(root).unwrap_or(&path);
            if let Some(set) = &include {
                if !set.is_match(rel) {
                    return None;
                }
            }
            if exclude
                .as_ref()
                .map(|set| set.is_match(rel))
                .unwrap_or(false)
            {
                return None;
            }
            Some(path)
        })
        .collect();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.concurrency)
        .build()
        .context("Unable to create scanner thread pool")?;

    let outcomes = pool.install(|| {
        files
            .par_iter()
            .map(|path| scan_file(root, path, options))
            .collect::<Vec<_>>()
    });

    let mut summary = ScanSummary {
        files_enumerated: files.len(),
        concurrency: options.concurrency,
        max_file_size_bytes: options.max_file_size_bytes,
        min_risk: options.min_risk,
        redact: options.redact,
        ..ScanSummary::default()
    };
    let mut findings = Vec::new();
    let mut skipped = Vec::new();

    for outcome in outcomes {
        if outcome.scanned {
            summary.files_scanned += 1;
        }
        if let Some(skipped_file) = outcome.skipped {
            match skipped_file.reason.as_str() {
                "binary" => summary.skipped_binary += 1,
                "too_large" => summary.skipped_too_large += 1,
                "unreadable" | "read_error" => summary.skipped_unreadable += 1,
                _ => {}
            }
            skipped.push(skipped_file);
        }
        findings.extend(outcome.findings);
    }

    findings.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line_number.cmp(&b.line_number))
    });
    summary.findings = findings.len();
    summary.skipped = skipped.len();

    Ok(ScanResult {
        summary,
        findings,
        skipped,
    })
}

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).with_context(|| format!("invalid glob: {pattern}"))?);
    }
    Ok(Some(
        builder.build().context("Unable to build glob matcher")?,
    ))
}

fn scan_file(root: &Path, path: &Path, options: &ScanOptions) -> FileOutcome {
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return FileOutcome {
                scanned: false,
                skipped: Some(SkippedFile {
                    file_path: rel,
                    reason: "unreadable".into(),
                }),
                findings: vec![],
            }
        }
    };

    if metadata.len() > options.max_file_size_bytes {
        return FileOutcome {
            scanned: false,
            skipped: Some(SkippedFile {
                file_path: rel,
                reason: "too_large".into(),
            }),
            findings: vec![],
        };
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return FileOutcome {
                scanned: false,
                skipped: Some(SkippedFile {
                    file_path: rel,
                    reason: "read_error".into(),
                }),
                findings: vec![],
            }
        }
    };

    if is_binary(&bytes) {
        return FileOutcome {
            scanned: false,
            skipped: Some(SkippedFile {
                file_path: rel,
                reason: "binary".into(),
            }),
            findings: vec![],
        };
    }

    let text = String::from_utf8_lossy(&bytes);
    if options.debug {
        eprintln!("[debug] scan file: {rel}");
    }
    let mut findings = Vec::new();
    for pattern in SECRET_PATTERNS.iter() {
        for caps in pattern.regex.captures_iter(&text) {
            let m = caps.name("secret").or_else(|| caps.get(0));
            let Some(secret_match) = m else { continue };
            let secret = secret_match.as_str();
            if let Some(validator) = pattern.validator {
                if !validator(secret) {
                    continue;
                }
            }
            if should_suppress(&rel, &text, secret) {
                continue;
            }
            let secret_entropy = entropy(secret);
            let risk = risk_score(
                pattern.id,
                pattern.base_risk,
                secret,
                &rel,
                &text,
                secret_match.start(),
            );
            if options.debug {
                eprintln!(
                    "[debug] candidate finding: file={rel} type={} risk={} entropy={:.2}",
                    pattern.id, risk, secret_entropy
                );
            }
            if risk < options.min_risk {
                if options.debug {
                    eprintln!(
                        "[debug] skipped_by_min_risk: file={rel} type={} risk={} min_risk={}",
                        pattern.id, risk, options.min_risk
                    );
                }
                continue;
            }
            let (line, column) = line_column(&text, secret_match.start());
            let snippet = line_snippet(&text, line, options.redact, secret, pattern.id);
            findings.push(Finding {
                finding_type: pattern.id.to_string(),
                title: pattern.title.to_string(),
                file_path: rel.clone(),
                line_number: line,
                column_number: column,
                risk_score: risk,
                entropy: secret_entropy,
                secret_hash: secret_hash(secret),
                secret: if options.redact {
                    redact_secret_for_pattern(pattern.id, secret)
                } else {
                    secret.to_string()
                },
                snippet,
            });
        }
    }

    FileOutcome {
        scanned: true,
        skipped: None,
        findings,
    }
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

fn should_suppress(file_path: &str, text: &str, _secret: &str) -> bool {
    let lower = file_path.to_ascii_lowercase();
    if lower.ends_with("package-lock.json") && text.contains("\"integrity\"") {
        return true;
    }
    false
}

fn risk_score(
    pattern_id: &str,
    base: u8,
    secret: &str,
    file_path: &str,
    text: &str,
    start_idx: usize,
) -> u8 {
    let lower_path = file_path.to_ascii_lowercase();
    let path_penalty = path_risk_penalty(&lower_path);

    if pattern_id == "taiwan_mobile" {
        return apply_risk_penalty(taiwan_mobile_risk_score(base, secret), path_penalty);
    }

    // Placeholders and documentation examples are rated as Low risk (30)
    let is_placeholder = is_likely_placeholder(secret);
    let is_doc_example = (lower_path.contains("readme")
        || lower_path.contains("docs/")
        || lower_path.contains("documentation")
        || lower_path.contains("guide"))
        && (secret.contains("example") || secret.contains("sample") || secret.contains("dummy"));

    if is_placeholder || is_doc_example {
        // Never inflate a pattern whose base score is already below 30
        return apply_risk_penalty(base.min(30), path_penalty);
    }

    let mut score = i16::from(base) - i16::from(path_penalty);
    if lower_path.ends_with(".env") || lower_path.contains(".env.") {
        score += 8;
    }
    if lower_path.contains("config")
        || lower_path.contains("settings")
        || lower_path.contains("workflow")
    {
        score += 5;
    }
    if lower_path.contains("readme") || lower_path.contains("docs/") {
        score -= 25;
    }
    if entropy(secret) < 3.0 && secret.len() < 24 {
        score -= 20;
    }
    if is_database_uri_pattern(pattern_id) && has_local_uri_host(secret) {
        score -= 20;
    }
    let lower_text = text.to_ascii_lowercase();
    if lower_text.contains("public key") || lower_text.contains("certificate") {
        // Don't penalise the citizen certificate pattern itself for containing the word "certificate"
        if pattern_id != "taiwan_citizen_certificate" {
            score -= 10;
        }
    }
    if pattern_id == "google_api_key"
        && (lower_path.contains("firebase")
            || lower_path.contains("google-services.json")
            || lower_path.contains("googleservice-info.plist")
            || lower_text.contains("firebaseconfig"))
    {
        score -= 55;
    }
    if pattern_id == "aws_access_key_id" && lower_text.contains("secret_access_key") {
        score += 10;
    }

    // Taiwan PDPA Contextual Risk Adjustments
    if pattern_id.starts_with("taiwan_") {
        let context_window = 150;
        let mut start_ctx = start_idx.saturating_sub(context_window);
        while start_ctx > 0 && !text.is_char_boundary(start_ctx) {
            start_ctx -= 1;
        }
        let mut end_ctx = (start_idx + secret.len() + context_window).min(text.len());
        while end_ctx < text.len() && !text.is_char_boundary(end_ctx) {
            end_ctx += 1;
        }
        let surrounding = text[start_ctx..end_ctx].to_lowercase();

        // taiwan_citizen_certificate uses additive scoring per keyword
        if pattern_id == "taiwan_citizen_certificate" {
            // +30 if the full phrase "自然人憑證" is present
            if surrounding.contains("自然人憑證") {
                score += 30;
            }
            // +10 if "自然人" is present (independently, even as part of 自然人憑證)
            if surrounding.contains("自然人") {
                score += 10;
            }
            // +10 if "憑證" is present (independently, even as part of 自然人憑證)
            if surrounding.contains("憑證") {
                score += 10;
            }
        } else {
            let kws = match pattern_id {
                "taiwan_national_id" => vec![
                    "身分證",
                    "身分證字號",
                    "national id",
                    "identity card",
                    "國民身分證",
                    "身分證統一編號",
                    "id",
                ],
                "taiwan_arc_ui" => {
                    vec!["統一證號", "居留證", "arc", "aprc", "resident certificate"]
                }
                "taiwan_mobile" => vec!["手機", "電話", "mobile", "cellphone", "phone"],
                "taiwan_einvoice_barcode" => vec![
                    "載具",
                    "手機條碼",
                    "條碼",
                    "barcode",
                    "einvoice",
                    "e-invoice",
                ],
                _ => vec![],
            };

            let mut has_kw = false;
            for kw in kws {
                if kw == "id" || kw == "arc" || kw == "aprc" {
                    let bytes = surrounding.as_bytes();
                    let mut start = 0;
                    while let Some(pos) = surrounding[start..].find(kw) {
                        let idx = start + pos;
                        let prev_ok = idx == 0
                            || (!bytes[idx - 1].is_ascii_alphanumeric() && bytes[idx - 1] != b'_');
                        let next_ok = idx + kw.len() == bytes.len()
                            || (!bytes[idx + kw.len()].is_ascii_alphanumeric()
                                && bytes[idx + kw.len()] != b'_');
                        if prev_ok && next_ok {
                            has_kw = true;
                            break;
                        }
                        start = idx + kw.len();
                    }
                    if has_kw {
                        break;
                    }
                } else if surrounding.contains(kw) {
                    has_kw = true;
                    break;
                }
            }

            if has_kw {
                score += 15;
            }
        }
    }

    score.clamp(0, 100) as u8
}

fn path_risk_penalty(lower_path: &str) -> u8 {
    if is_python_site_packages_path(lower_path) {
        15
    } else {
        0
    }
}

fn apply_risk_penalty(score: u8, penalty: u8) -> u8 {
    score.saturating_sub(penalty)
}

fn is_python_site_packages_path(lower_path: &str) -> bool {
    let mut segments = lower_path.split('/');
    while let Some(segment) = segments.next() {
        if segment == "lib" {
            let Some(python_segment) = segments.next() else {
                continue;
            };
            let Some(site_packages_segment) = segments.next() else {
                continue;
            };
            if python_segment.starts_with("python") && site_packages_segment == "site-packages" {
                return true;
            }
        }
    }
    false
}

fn is_database_uri_pattern(pattern_id: &str) -> bool {
    matches!(pattern_id, "postgres_uri" | "mongodb_uri" | "redis_uri")
}

fn has_local_uri_host(secret: &str) -> bool {
    Url::parse(secret)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|host| {
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0"
        })
}

fn taiwan_mobile_risk_score(base: u8, secret: &str) -> u8 {
    if is_strict_taiwan_mobile_format(secret) {
        base
    } else {
        base.saturating_sub(10)
    }
}

fn is_strict_taiwan_mobile_format(secret: &str) -> bool {
    let bytes = secret.as_bytes();
    matches!(bytes.len(), 10 | 11 | 12 | 13 | 15)
        && (is_strict_local_taiwan_mobile(bytes)
            || is_strict_plus_taiwan_mobile(bytes)
            || is_strict_bare_country_taiwan_mobile(bytes))
}

fn is_strict_local_taiwan_mobile(bytes: &[u8]) -> bool {
    (bytes.len() == 10 && bytes.starts_with(b"09") && bytes.iter().all(u8::is_ascii_digit))
        || (bytes.len() == 11
            && bytes.starts_with(b"09")
            && bytes[4] == b'-'
            && bytes[..4].iter().all(u8::is_ascii_digit)
            && bytes[5..].iter().all(u8::is_ascii_digit))
}

fn is_strict_plus_taiwan_mobile(bytes: &[u8]) -> bool {
    (bytes.len() == 15
        && bytes.starts_with(b"+886-9")
        && bytes[8] == b'-'
        && bytes[1..4].iter().all(u8::is_ascii_digit)
        && bytes[5..8].iter().all(u8::is_ascii_digit)
        && bytes[9..].iter().all(u8::is_ascii_digit))
        || (bytes.len() == 13
            && bytes.starts_with(b"+8869")
            && bytes[1..].iter().all(u8::is_ascii_digit))
}

fn is_strict_bare_country_taiwan_mobile(bytes: &[u8]) -> bool {
    bytes.len() == 12 && bytes.starts_with(b"8869") && bytes.iter().all(u8::is_ascii_digit)
}

fn entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for b in value.bytes() {
        *counts.entry(b).or_insert(0usize) += 1;
    }
    let len = value.len() as f64;
    counts.values().fold(0.0, |acc, count| {
        let p = *count as f64 / len;
        acc - p * p.log2()
    })
}

fn line_column(text: &str, byte_offset: usize) -> (usize, usize) {
    let prefix = &text[..byte_offset.min(text.len())];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let last_newline = prefix.rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    let column = prefix[last_newline..].chars().count() + 1;
    (line, column)
}

fn line_snippet(
    text: &str,
    line_number: usize,
    redact: bool,
    secret: &str,
    pattern_id: &str,
) -> String {
    let line = text
        .lines()
        .nth(line_number.saturating_sub(1))
        .unwrap_or_default()
        .trim();
    let snippet = if redact {
        line.replace(secret, &redact_secret_for_pattern(pattern_id, secret))
    } else {
        line.to_string()
    };
    if snippet.chars().count() > 220 {
        snippet.chars().take(220).collect::<String>() + "…"
    } else {
        snippet
    }
}

pub fn secret_hash(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(&digest[..8]))
}

pub fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        return "[REDACTED]".to_string();
    }
    let start: String = secret.chars().take(4).collect();
    let end: String = secret
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}…{end}")
}

pub fn redact_secret_for_pattern(pattern_id: &str, secret: &str) -> String {
    if pattern_id.starts_with("taiwan_") {
        if secret.len() <= 4 {
            return "[REDACTED]".to_string();
        }
        let start: String = secret.chars().take(2).collect();
        let end: String = secret
            .chars()
            .rev()
            .take(2)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        format!("{start}…{end}")
    } else {
        redact_secret(secret)
    }
}
